// server.js
import express from "express";
import multer from "multer";
import cors from "cors";
import { neon } from "@neondatabase/serverless";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
import fs from "fs";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sql = neon(process.env.DATABASE_URL);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: "/tmp" });

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const generateToken = (user) =>
  jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing auth token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Invalid auth token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalid or expired" });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path, {
    folder: "Hackathon",
  });
  fs.unlinkSync(file.path);
  return result.secure_url;
};

app.get("/", (req, res) => {
  res.send("Welcome to Hackathon API");
});

// User Management

//  REGISTER
app.post("/auth/register", upload.single("image"), async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    let imageUrl = null;

    if (req.file) {
      imageUrl = await uploadImage(req.file);
    }

    // Check if user exists
    const existingUser = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (existingUser.length > 0)
      return res.status(400).json({ error: "Email already registered" });

    // Insert user
    const insertedUser = await sql`
      INSERT INTO users (email, password, name, profile_image_url, role)
      VALUES (${email}, ${hashedPassword}, ${name}, ${imageUrl}, ${role})
      RETURNING *
    `;
    const user = insertedUser[0];

    res.status(201).json({
      message: "User registered successfully",
      token: generateToken(user),
      user,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await sql`SELECT * FROM users WHERE email = ${email}`;
    const user = users[0];
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ error: "Invalid email or password" });

    const token = generateToken(user);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET PROFILE
app.get("/users/me", authenticateToken, async (req, res) => {
  try {
    const users = await sql`SELECT * FROM users WHERE id = ${req.user.id}`;
    const user = users[0];
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE PROFILE
app.put(
  "/users/me",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const { name, email, phoneNumber } = req.body;
      let updates = [];
      let values = [];
      let idx = 1;

      if (name) {
        updates.push(`name = $${idx++}`);
        values.push(name);
      }
      if (email) {
        updates.push(`email = $${idx++}`);
        values.push(email);
      }

      let imageUrl;
      if (req.file) {
        imageUrl = await uploadImage(req.file);
        updates.push(`profile_image_url = $${idx++}`);
        values.push(imageUrl);
      }

      if (updates.length === 0)
        return res.status(400).json({ error: "No updates provided" });
      values.push(req.user.id);
      const updateQuery = `UPDATE users SET ${updates.join(
        ", "
      )} WHERE id = $${idx} RETURNING *`;
      const updated = await sql.unsafe(updateQuery, values);
      res.json(updated[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// --- Forgot Password ---
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const users = await sql`SELECT * FROM users WHERE email = ${email}`;
    const user = users[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    const resetUrl = `https://localhost:3000/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: `"Hackathon" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `<p>Click below to reset your password:</p><a href="${resetUrl}">${resetUrl}</a><p>Link expires in 15 minutes.</p>`,
    });

    res.json({ message: "Reset email sent if the account exists." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- Reset Password ---
app.post("/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "Token and new password required" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const users = await sql`SELECT * FROM users WHERE id = ${userId}`;
    const user = users[0];
    if (!user)
      return res.status(400).json({ error: "Invalid token or user not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await sql`UPDATE users SET password = ${hashedPassword} WHERE id = ${userId}`;

    res.json({ message: "Password has been reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

// INVESTOR MARKETPLACE

// Create Project
app.post(
  "/investor/projects",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "farmer")
      return res
        .status(403)
        .json({ error: "Only farmers can create projects" });

    const { project_title, description, funding_goal } = req.body;
    if (!project_title || !funding_goal)
      return res
        .status(400)
        .json({ error: "Title and funding goal are required" });

    try {
      let imageUrl = null;
      if (req.file) imageUrl = await uploadImage(req.file);

      const project = await sql`
      INSERT INTO projects (farmer_id, project_title, description, funding_goal, amount_raised, status)
      VALUES (${req.user.id}, ${project_title}, ${description}, ${funding_goal}, 0, 'open')
      RETURNING *
    `;
      res.status(201).json(project[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Get all projects
app.get("/investor/projects", async (req, res) => {
  try {
    const projects = await sql`SELECT * FROM projects ORDER BY created_at DESC`;
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fund a project
app.post("/investor/fund/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "investor")
    return res.status(403).json({ error: "Only investors can fund projects" });

  const { amount } = req.body;
  if (!amount || amount <= 0)
    return res.status(400).json({ error: "Funding amount required" });

  try {
    const projects =
      await sql`SELECT * FROM projects WHERE id = ${req.params.id}`;
    const project = projects[0];
    if (!project) return res.status(404).json({ error: "Project not found" });
    if (project.status !== "open")
      return res.status(400).json({ error: "Project not open for funding" });

    const newRaised = Number(project.amount_raised) + Number(amount);
    let status = project.status;
    if (newRaised >= project.funding_goal) status = "funded";

    const updated = await sql`
      UPDATE projects
      SET amount_raised = ${newRaised}, status = ${status}
      WHERE id = ${project.id}
      RETURNING *
    `;

    // Notify farmer
    await sql`
      INSERT INTO notifications (user_id, message)
      VALUES (${project.farmer_id}, 'Your project "${project.project_title}" has received funding of $${amount}')
    `;

    res.json(updated[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Farm Rentals ---
// Add rental (farm or equipment)
app.post(
  "/rentals/add",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "farmer")
      return res.status(403).json({ error: "Only farmers can list rentals" });

    const { type, name, description, price, location } = req.body;
    if (!type || !["farm", "equipment"].includes(type)) {
      return res
        .status(400)
        .json({ error: 'Type must be "farm" or "equipment"' });
    }
    if (!name || !price)
      return res.status(400).json({ error: "Name and price required" });

    try {
      let imageUrl = null;
      if (req.file) imageUrl = await uploadImage(req.file);

    const rental = await sql`
  INSERT INTO rentals (owner_id, type, name, description, price, location, image_url)
  VALUES (${req.user.id}, ${type}, ${name}, ${description}, ${price}, ${location}, ${imageUrl})
  RETURNING *
`;

      res.status(201).json(rental[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);


// List rentals (both farms and equipment, with filter option)
app.get("/rentals/list", async (req, res) => {
  const { type } = req.query; // optional filter
  try {
    let rentals;
    if (type && ["farm", "equipment"].includes(type)) {
      rentals =
        await sql`SELECT * FROM rentals WHERE type = ${type} ORDER BY created_at DESC`;
    } else {
      rentals = await sql`SELECT * FROM rentals ORDER BY created_at DESC`;
    }
    res.json(rentals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Book rental with duration
app.post("/rentals/book/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer")
    return res.status(403).json({ error: "Only farmers can book rentals" });

  const { start_date, start_time, end_date, end_time } = req.body;
  if (!start_date || !start_time || !end_date || !end_time) {
    return res
      .status(400)
      .json({ error: "Start and end date + time required" });
  }

  try {
    // Combine date + time into proper timestamps for calculations
    const start_datetime = new Date(`${start_date}T${start_time}:00`);
    const end_datetime = new Date(`${end_date}T${end_time}:00`);

    if (isNaN(start_datetime) || isNaN(end_datetime)) {
      return res.status(400).json({ error: "Invalid date or time format" });
    }
    if (end_datetime <= start_datetime) {
      return res
        .status(400)
        .json({ error: "End time must be after start time" });
    }

    const rentals =
      await sql`SELECT * FROM rentals WHERE id = ${req.params.id}`;
    const rental = rentals[0];
    if (!rental) return res.status(404).json({ error: "Rental not found" });

    // Conflict check using date + time as full timestamp
    const conflicts = await sql`
      SELECT * FROM bookings
      WHERE rental_id = ${rental.id}
      AND status = 'active'
      AND (start_date + start_time, end_date + end_time)
          OVERLAPS (${start_datetime}::timestamp, ${end_datetime}::timestamp)
    `;
    if (conflicts.length > 0) {
      return res.status(400).json({
        error: "Rental not available for selected time",
      });
    }

    // --- Duration calculation ---
    const diffMs = end_datetime - start_datetime;
    const hours = diffMs / (1000 * 60 * 60);
    const days = diffMs / (1000 * 60 * 60 * 24);

    // --- Cost calculation ---
    let totalCost = 0;
    if (rental.price_per_hour) {
      totalCost = Math.ceil(hours) * rental.price_per_hour;
    } else if (rental.price_per_day) {
      totalCost = Math.ceil(days) * rental.price_per_day;
    } else if (rental.price_per_month) {
      const months = Math.ceil(days / 30);
      totalCost = months * rental.price_per_month;
    }

    // Save booking
    const booking = await sql`
      INSERT INTO bookings 
        (rental_id, farmer_id, start_date, start_time, end_date, end_time, total_cost)
      VALUES 
        (${rental.id}, ${req.user.id}, ${start_date}, ${start_time}, ${end_date}, ${end_time}, ${totalCost})
      RETURNING *
    `;

    // Notify owner
    await sql`
      INSERT INTO notifications (user_id, message)
      VALUES (
        ${rental.owner_id}, 
        'Your ${rental.type} "${rental.name}" has been booked from ${start_date} ${start_time} to ${end_date} ${end_time}.'
      )
    `;

    res.status(201).json(booking[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// --- Notifications ---

// Get my notifications
app.get("/notifications", authenticateToken, async (req, res) => {
  try {
    const notes = await sql`
      SELECT * FROM notifications WHERE user_id = ${req.user.id} ORDER BY created_at DESC
    `;
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Mark notification as read
app.put("/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const updated = await sql`
      UPDATE notifications SET read = true WHERE id = ${req.params.id} AND user_id = ${req.user.id}
      RETURNING *
    `;
    if (!updated.length)
      return res.status(404).json({ error: "Notification not found" });
    res.json(updated[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// --- DASHBOARD ENDPOINTS ---

// Farmer: Get my projects
app.get("/investor/my-projects", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") 
    return res.status(403).json({ error: "Only farmers can view their projects" });

  try {
    const projects = await sql`
      SELECT * FROM projects WHERE farmer_id = ${req.user.id} ORDER BY created_at DESC
    `;
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Farmer: Get my rentals
app.get("/rentals/my-listings", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") 
    return res.status(403).json({ error: "Only farmers can view their rentals" });

  try {
    const rentals = await sql`
      SELECT * FROM rentals WHERE owner_id = ${req.user.id} ORDER BY created_at DESC
    `;
    res.json(rentals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Farmer: Get my bookings
app.get("/bookings/my-bookings", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") 
    return res.status(403).json({ error: "Only farmers can view their bookings" });

  try {
    const bookings = await sql`
      SELECT b.*, r.name AS rental_name, r.type AS rental_type
      FROM bookings b
      JOIN rentals r ON b.rental_id = r.id
      WHERE b.farmer_id = ${req.user.id}
      ORDER BY b.created_at DESC
    `;
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// --- ADMIN DASHBOARD ENDPOINTS ---

// Admin: Get all users
app.get("/admin/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view all users" });

  try {
    const users = await sql`SELECT id, name, email, role, phone_number, created_at FROM users ORDER BY created_at DESC`;
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all projects
app.get("/admin/projects", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view all projects" });

  try {
    const projects = await sql`
      SELECT p.*, u.name AS farmer_name 
      FROM projects p
      JOIN users u ON p.farmer_id = u.id
      ORDER BY p.created_at DESC
    `;
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all rentals
app.get("/admin/rentals", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view all rentals" });

  try {
    const rentals = await sql`
      SELECT r.*, u.name AS owner_name 
      FROM rentals r
      JOIN users u ON r.owner_id = u.id
      ORDER BY r.created_at DESC
    `;
    res.json(rentals);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all bookings
app.get("/admin/bookings", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view all bookings" });

  try {
    const bookings = await sql`
      SELECT b.*, r.name AS rental_name, r.type AS rental_type, u.name AS farmer_name
      FROM bookings b
      JOIN rentals r ON b.rental_id = r.id
      JOIN users u ON b.farmer_id = u.id
      ORDER BY b.created_at DESC
    `;
    res.json(bookings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Get all notifications
app.get("/admin/notifications", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view all notifications" });

  try {
    const notifications = await sql`
      SELECT n.*, u.name AS user_name 
      FROM notifications n
      JOIN users u ON n.user_id = u.id
      ORDER BY n.created_at DESC
    `;
    res.json(notifications);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});

