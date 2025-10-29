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
  try {
    const result = await cloudinary.uploader.upload(file.path, {
      folder: "Hackathon",
    });
    fs.unlinkSync(file.path);
    return result.secure_url;
  } catch (error) {
    fs.unlinkSync(file.path);
    throw error;
  }
};

app.get("/", (req, res) => {
  res.send("Welcome to Hackathon API");
});

// User Management

// REGISTER
app.post("/auth/register", upload.single("image"), async (req, res) => {
  const { email, password, name, role, phoneNumber } = req.body;
  if (!email || !password || !name)
    return res
      .status(400)
      .json({ error: "Email, password, and name are required" });

  // Validate role
  if (!["farmer", "investor", "admin"].includes(role)) {
    return res
      .status(400)
      .json({ error: "Invalid role. Must be farmer, investor, or admin." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    let imageUrl = null;

    if (req.file) {
      imageUrl = await uploadImage(req.file);
    }

    // Check if user exists
    const existingUser = await sql`SELECT id FROM users WHERE email = ${email}`;
    if (existingUser.length > 0)
      return res.status(400).json({ error: "Email already registered" });

    // Insert user
    const insertedUser = await sql`
      INSERT INTO users (email, password, name, profile_image_url, role, phone_number)
      VALUES (${email}, ${hashedPassword}, ${name}, ${imageUrl}, ${role}, ${
      phoneNumber || null
    })
      RETURNING id, name, email, role, profile_image_url, phone_number, created_at
    `;
    const user = insertedUser[0];

    res.status(201).json({
      message: "User registered successfully",
      token: generateToken(user),
      user,
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const users = await sql`
      SELECT id, name, email, role, profile_image_url, phone_number, created_at, password 
      FROM users WHERE email = ${email}
    `;
    const user = users[0];
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ error: "Invalid email or password" });

    const { password: _, ...safeUser } = user;
    const token = generateToken(safeUser);
    res.json({ token, user: safeUser });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET PROFILE
app.get("/users/me", authenticateToken, async (req, res) => {
  try {
    const users = await sql`
      SELECT id, name, email, role, profile_image_url, phone_number, created_at 
      FROM users WHERE id = ${req.user.id}
    `;
    const user = users[0];
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({ error: "Internal server error" });
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

      if (name !== undefined) {
        updates.push(`name = $${idx++}`);
        values.push(name);
      }
      if (email !== undefined) {
        // Check if new email exists
        if (email && email !== req.user.email) {
          const existing =
            await sql`SELECT id FROM users WHERE email = ${email}`;
          if (existing.length > 0) {
            return res.status(400).json({ error: "Email already in use" });
          }
        }
        updates.push(`email = $${idx++}`);
        values.push(email);
      }
      if (phoneNumber !== undefined) {
        updates.push(`phone_number = $${idx++}`);
        values.push(phoneNumber);
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
      )} WHERE id = $${idx} RETURNING id, name, email, role, profile_image_url, phone_number, created_at`;
      const updated = await sql.unsafe(updateQuery, values);
      if (updated.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json(updated[0]);
    } catch (err) {
      console.error("Update profile error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// --- Forgot Password ---
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const users = await sql`SELECT id, email FROM users WHERE email = ${email}`;
    const user = users[0];
    if (!user) {
      // Don't reveal if user exists
      return res.json({
        message: "If the account exists, a reset email has been sent.",
      });
    }

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`; // Changed to http for local

    await transporter.sendMail({
      from: `"Hackathon App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link expires in 15 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `,
    });

    res.json({
      message: "If the account exists, a reset email has been sent.",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Failed to send reset email" });
  }
});

// --- Reset Password ---
app.post("/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 6) {
    return res
      .status(400)
      .json({ error: "Valid token and new password (min 6 chars) required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const users = await sql`SELECT id FROM users WHERE id = ${userId}`;
    const user = users[0];
    if (!user) {
      return res.status(400).json({ error: "Invalid token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await sql`UPDATE users SET password = ${hashedPassword} WHERE id = ${userId}`;

    res.json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
      return res.status(400).json({ error: "Invalid or expired token" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// INVESTOR MARKETPLACE

// Create Project
app.post(
  "/investor/projects",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "farmer") {
      return res
        .status(403)
        .json({ error: "Only farmers can create projects" });
    }

    const { project_title, description, funding_goal } = req.body;
    if (!project_title || !funding_goal || funding_goal <= 0) {
      return res
        .status(400)
        .json({ error: "Valid title and funding goal are required" });
    }

    try {
      let imageUrl = null;
      if (req.file) {
        imageUrl = await uploadImage(req.file);
      }

      const project = await sql`
        INSERT INTO projects (farmer_id, project_title, description, funding_goal, amount_raised, status, image_url)
        VALUES (${req.user.id}, ${project_title}, ${
        description || null
      }, ${Number(funding_goal)}, 0, 'open', ${imageUrl})
        RETURNING *
      `;
      res.status(201).json(project[0]);
    } catch (err) {
      console.error("Create project error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Get all projects
app.get("/investor/projects", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;
    const projects = await sql`
      SELECT *, 
        (SELECT name FROM users WHERE id = farmer_id) AS farmer_name
      FROM projects 
      ORDER BY created_at DESC 
      LIMIT ${Number(limit)} OFFSET ${Number(offset)}
    `;
    const total = await sql`SELECT COUNT(*) FROM projects`;
    res.json({
      projects,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total[0].count),
        pages: Math.ceil(Number(total[0].count) / Number(limit)),
      },
    });
  } catch (err) {
    console.error("Get projects error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Fund a project
app.post("/investor/fund/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "investor") {
    return res.status(403).json({ error: "Only investors can fund projects" });
  }

  const { amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: "Valid funding amount required" });
  }

  const projectId = Number(req.params.id);

  try {
    // Use transaction for atomicity
    const result = await sql`BEGIN`;
    try {
      const projects =
        await sql`SELECT * FROM projects WHERE id = ${projectId} FOR UPDATE`;
      const project = projects[0];
      if (!project) {
        await sql`ROLLBACK`;
        return res.status(404).json({ error: "Project not found" });
      }
      if (project.status !== "open") {
        await sql`ROLLBACK`;
        return res.status(400).json({ error: "Project not open for funding" });
      }

      const newRaised = Number(project.amount_raised) + Number(amount);
      let status = project.status;
      if (newRaised >= project.funding_goal) status = "funded";

      const updated = await sql`
        UPDATE projects
        SET amount_raised = ${newRaised}, status = ${status}
        WHERE id = ${projectId}
        RETURNING *
      `;

      // Record investment
      await sql`
        INSERT INTO investments (investor_id, project_id, amount, created_at)
        VALUES (${req.user.id}, ${projectId}, ${Number(amount)}, now())
      `;

      // Notify farmer
      const notifyMsg = `Your project "${project.project_title}" has received $${amount} in funding!`;
      await sql.unsafe(
        "INSERT INTO notifications (user_id, message, read) VALUES ($1, $2, $3)",
        [project.farmer_id, notifyMsg, false]
      );

      await sql`COMMIT`;
      res.json({ ...updated[0], fundedAmount: Number(amount) });
    } catch (txErr) {
      await sql`ROLLBACK`;
      throw txErr;
    }
  } catch (err) {
    console.error("Fund project error:", err);
    // If investments table doesn't exist, it's ok, project still updates but log
    if (err.message.includes("investments")) {
      console.warn("Investments table not found, skipping investment record");
      // Still update project without transaction for investments
      try {
        const projects =
          await sql`SELECT * FROM projects WHERE id = ${projectId}`;
        const project = projects[0];
        if (project && project.status === "open") {
          const newRaised = Number(project.amount_raised) + Number(amount);
          let status = project.status;
          if (newRaised >= project.funding_goal) status = "funded";
          const updated = await sql`
            UPDATE projects SET amount_raised = ${newRaised}, status = ${status} WHERE id = ${projectId} RETURNING *
          `;
          const notifyMsg = `Your project "${project.project_title}" has received $${amount} in funding!`;
          await sql.unsafe(
            "INSERT INTO notifications (user_id, message, read) VALUES ($1, $2, $3)",
            [project.farmer_id, notifyMsg, false]
          );
          res.json(updated[0]);
          return;
        }
      } catch (fallbackErr) {
        console.error("Fallback update error:", fallbackErr);
      }
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Farm Rentals ---
// Add rental (farm or equipment)
app.post(
  "/rentals/add",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "farmer") {
      return res.status(403).json({ error: "Only farmers can list rentals" });
    }

    const {
      type,
      name,
      description,
      location,
      price_per_day,
      price_per_hour,
      price_per_month,
    } = req.body;

    // Validate type
    if (!type || !["farm", "equipment"].includes(type)) {
      return res
        .status(400)
        .json({ error: 'Type must be either "farm" or "equipment"' });
    }

    // Validate required fields
    if (
      !name ||
      !description ||
      !location ||
      !price_per_day ||
      Number(price_per_day) <= 0
    ) {
      return res.status(400).json({
        error:
          "Name, description, location, and valid price per day are required",
      });
    }

    try {
      let imageUrl = null;
      if (req.file) {
        imageUrl = await uploadImage(req.file);
      }

      const rental = await sql`
        INSERT INTO rentals (
          owner_id,
          type,
          name,
          description,
          location,
          price_per_day,
          price_per_hour,
          price_per_month,
          image_url
        )
        VALUES (
          ${req.user.id},
          ${type},
          ${name},
          ${description},
          ${location},
          ${Number(price_per_day)},
          ${price_per_hour ? Number(price_per_hour) : null},
          ${price_per_month ? Number(price_per_month) : null},
          ${imageUrl}
        )
        RETURNING *
      `;

      res.status(201).json(rental[0]);
    } catch (err) {
      console.error("Add rental error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ✅ List bookings (auto-refresh status + pagination + optional filter by farmer)
app.get("/bookings/list", authenticateToken, async (req, res) => {
  const { page = 1, limit = 10, farmer_id } = req.query;

  try {
    // 🧠 Step 0: Auto-complete expired bookings
    await sql`
      UPDATE bookings
      SET status = 'completed'
      WHERE status = 'active'
      AND (end_date + end_time) <= NOW()
    `;

    // 🧭 Step 1: Base query with rental and user info
    let query = sql`
      SELECT b.*, r.name AS rental_name, r.type AS rental_type, u.name AS farmer_name
      FROM bookings b
      JOIN rentals r ON b.rental_id = r.id
      JOIN users u ON b.farmer_id = u.id
    `;

    let countQuery = sql`SELECT COUNT(*) FROM bookings b`;

    // 🧩 Optional filter by farmer_id
    if (farmer_id) {
      query = sql`
        SELECT b.*, r.name AS rental_name, r.type AS rental_type, u.name AS farmer_name
        FROM bookings b
        JOIN rentals r ON b.rental_id = r.id
        JOIN users u ON b.farmer_id = u.id
        WHERE b.farmer_id = ${farmer_id}
      `;
      countQuery = sql`
        SELECT COUNT(*) 
        FROM bookings b
        WHERE b.farmer_id = ${farmer_id}
      `;
    }

    // 🧾 Step 2: Pagination
    const offset = (Number(page) - 1) * Number(limit);
    query.append(sql` ORDER BY b.created_at DESC LIMIT ${Number(limit)} OFFSET ${offset}`);

    // 🗂 Step 3: Execute
    const bookings = await query;
    const totalRes = await countQuery;
    const total = totalRes[0].count;

    res.json({
      bookings,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total),
        pages: Math.ceil(Number(total) / Number(limit)),
      },
    });
  } catch (err) {
    console.error("List bookings error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

// ✅ Book a rental (auto-disable availability + completed booking check)
app.post("/rentals/book/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") {
    return res.status(403).json({ error: "Only farmers can book rentals" });
  }

  const { start_date, start_time, end_date, end_time } = req.body;
  const rentalId = Number(req.params.id);

  if (!start_date || !start_time || !end_date || !end_time) {
    return res
      .status(400)
      .json({ error: "Start and end date + time are required." });
  }

  if (isNaN(rentalId)) {
    return res.status(400).json({ error: "Invalid rental ID." });
  }

  try {
    const start_datetime = new Date(`${start_date}T${start_time}:00`);
    const end_datetime = new Date(`${end_date}T${end_time}:00`);

    if (end_datetime <= start_datetime) {
      return res
        .status(400)
        .json({ error: "End time must be after start time." });
    }

    // 🧠 Step 0: Auto-complete expired bookings
    await sql`
      UPDATE bookings
      SET status = 'completed'
      WHERE status = 'active'
      AND (end_date + end_time) <= NOW()
    `;

    // 🧠 Step 1: Refresh rental availability based on completed bookings
    await sql`
      UPDATE rentals
      SET is_available = true
      WHERE id IN (
        SELECT rental_id FROM bookings
        WHERE status = 'completed'
      )
    `;

    // 🧭 Step 2: Fetch rental
    const rentals = await sql`SELECT * FROM rentals WHERE id = ${rentalId}`;
    const rental = rentals[0];
    if (!rental)
      return res.status(404).json({ error: "Rental not found." });
    if (!rental.is_available) {
      return res
        .status(400)
        .json({ error: "This rental is currently unavailable." });
    }

    // 💰 Step 3: Calculate pricing
    const diffMs = end_datetime - start_datetime;
    const hours = diffMs / (1000 * 60 * 60);
    const days = diffMs / (1000 * 60 * 60 * 24);

    const pricePerHour = Number(rental.price_per_hour) || 0;
    const pricePerDay = Number(rental.price_per_day) || 0;
    const pricePerMonth = Number(rental.price_per_month) || 0;

    let totalCost = 0;
    if (pricePerHour > 0 && hours < 24) {
      totalCost = Math.ceil(hours) * pricePerHour;
    } else if (pricePerDay > 0 && days < 30) {
      totalCost = Math.ceil(days) * pricePerDay;
    } else if (pricePerMonth > 0) {
      totalCost = Math.ceil(days / 30) * pricePerMonth;
    } else {
      return res.status(400).json({
        error: "This rental has no valid pricing configured.",
        debug: { pricePerHour, pricePerDay, pricePerMonth },
      });
    }

    // 🧾 Step 4: Begin transaction
    await sql`BEGIN`;
    try {
      // Create booking with 'active' status
      const booking = await sql`
        INSERT INTO bookings (rental_id, farmer_id, start_date, start_time, end_date, end_time, total_cost, status)
        VALUES (${rentalId}, ${req.user.id}, ${start_date}, ${start_time}, ${end_date}, ${end_time}, ${totalCost}, 'active')
        RETURNING *
      `;

      // Mark rental unavailable immediately
      await sql`UPDATE rentals SET is_available = false WHERE id = ${rentalId}`;

      // Notify owner
      const bookingNotify = `Your ${rental.type} "${rental.name}" has been booked by ${req.user.name} from ${start_date} ${start_time} to ${end_date} ${end_time} for ₦${totalCost}.`;
      await sql`
        INSERT INTO notifications (user_id, message, read)
        VALUES (${rental.owner_id}, ${bookingNotify}, ${false})
      `;

      await sql`COMMIT`;

      res.status(201).json({
        message: "Booking successful!",
        booking: booking[0],
      });
    } catch (txErr) {
      await sql`ROLLBACK`;
      console.error("Booking transaction failed:", txErr);
      res.status(500).json({ error: "Booking transaction failed." });
    }
  } catch (err) {
    console.error("Book rental error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});


// --- Notifications ---
// ✅ Get my notifications (with pagination + unread filter)
app.get("/notifications", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, unread = "false" } = req.query;

    const offset = (Number(page) - 1) * Number(limit);

    // 🧠 Base WHERE condition
    let whereClause = sql`WHERE user_id = ${req.user.id}`;
    if (unread === "true") {
      whereClause = sql`WHERE user_id = ${req.user.id} AND read = false`;
    }

    // 🗂 Fetch notifications
    const notifications = await sql`
      SELECT *
      FROM notifications
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ${Number(limit)} OFFSET ${offset}
    `;

    // 📊 Count total
    const totalRes = await sql`
      SELECT COUNT(*) FROM notifications ${whereClause}
    `;
    const total = Number(totalRes[0].count);

    res.json({
      notifications,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / Number(limit)),
      },
    });
  } catch (err) {
    console.error("Get notifications error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Mark notification as read
app.put("/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const notificationId = Number(req.params.id);
    const updated = await sql`
      UPDATE notifications 
      SET read = true, updated_at = now() 
      WHERE id = ${notificationId} AND user_id = ${req.user.id}
      RETURNING *
    `;
    if (updated.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }
    res.json(updated[0]);
  } catch (err) {
    console.error("Mark read error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Mark all notifications as read
app.put("/notifications/read-all", authenticateToken, async (req, res) => {
  try {
    const updated = await sql`
      UPDATE notifications 
      SET read = true, updated_at = now() 
      WHERE user_id = ${req.user.id} AND read = false
      RETURNING *
    `;
    res.json({ message: `Marked ${updated.length} notifications as read` });
  } catch (err) {
    console.error("Mark all read error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- DASHBOARD ENDPOINTS ---

// Get projects (my or all based on role)
app.get("/investor/my-projects", authenticateToken, async (req, res) => {
  try {
    let projects;
    if (req.user.role === "farmer") {
      projects = await sql`
        SELECT * FROM projects WHERE farmer_id = ${req.user.id} ORDER BY created_at DESC
      `;
    } else {
      projects = await sql`SELECT * FROM projects ORDER BY created_at DESC`;
    }
    res.json(projects);
  } catch (err) {
    console.error("Get projects error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Investor: Get my investments
app.get("/investor/my-investments", authenticateToken, async (req, res) => {
  if (req.user.role !== "investor") {
    return res
      .status(403)
      .json({ error: "Only investors can view their investments" });
  }

  try {
    const investments = await sql`
      SELECT i.*, p.project_title, p.description, p.status, u.name AS farmer_name
      FROM investments i
      JOIN projects p ON i.project_id = p.id
      LEFT JOIN users u ON p.farmer_id = u.id
      WHERE i.investor_id = ${req.user.id}
      ORDER BY i.created_at DESC
    `;
    res.json(investments);
  } catch (err) {
    console.error("Get investments error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Farmer: Get my rentals
app.get("/rentals/my-listings", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") {
    return res
      .status(403)
      .json({ error: "Only farmers can view their rentals" });
  }

  try {
    const rentals = await sql`
      SELECT * FROM rentals WHERE owner_id = ${req.user.id} ORDER BY created_at DESC
    `;
    res.json(rentals);
  } catch (err) {
    console.error("Get my rentals error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Farmer: Get my bookings
app.get("/bookings/my-bookings", authenticateToken, async (req, res) => {
  if (req.user.role !== "farmer") {
    return res
      .status(403)
      .json({ error: "Only farmers can view their bookings" });
  }

  try {
    const bookings = await sql`
      SELECT b.*, r.name AS rental_name, r.type AS rental_type, r.location, r.price_per_day
      FROM bookings b
      JOIN rentals r ON b.rental_id = r.id
      WHERE b.farmer_id = ${req.user.id}
      ORDER BY b.created_at DESC
    `;
    res.json(bookings);
  } catch (err) {
    console.error("Get my bookings error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- ADMIN DASHBOARD ENDPOINTS ---

// Admin: Get all users
app.get("/admin/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can view all users" });
  }

  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    const users = await sql`
      SELECT id, name, email, role, phone_number, created_at, profile_image_url 
      FROM users 
      ORDER BY created_at DESC 
      LIMIT ${Number(limit)} OFFSET ${offset}
    `;
    const total = await sql`SELECT COUNT(*) FROM users`;
    res.json({
      users,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(total[0].count),
        pages: Math.ceil(Number(total[0].count) / Number(limit)),
      },
    });
  } catch (err) {
    console.error("Admin get users error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get all projects
app.get("/admin/projects", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can view all projects" });
  }

  try {
    const projects = await sql`
      SELECT p.*, u.name AS farmer_name, u.email AS farmer_email
      FROM projects p
      JOIN users u ON p.farmer_id = u.id
      ORDER BY p.created_at DESC
    `;
    res.json(projects);
  } catch (err) {
    console.error("Admin get projects error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get all rentals
app.get("/admin/rentals", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can view all rentals" });
  }

  try {
    const rentals = await sql`
      SELECT r.*, u.name AS owner_name, u.email AS owner_email
      FROM rentals r
      JOIN users u ON r.owner_id = u.id
      ORDER BY r.created_at DESC
    `;
    res.json(rentals);
  } catch (err) {
    console.error("Admin get rentals error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get all bookings
app.get("/admin/bookings", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can view all bookings" });
  }

  try {
    const bookings = await sql`
      SELECT b.*, 
             r.name AS rental_name, 
             r.type AS rental_type, 
             r.location,
             fu.name AS farmer_name,
             ou.name AS owner_name
      FROM bookings b
      JOIN rentals r ON b.rental_id = r.id
      JOIN users fu ON b.farmer_id = fu.id
      JOIN users ou ON r.owner_id = ou.id
      ORDER BY b.created_at DESC
    `;
    res.json(bookings);
  } catch (err) {
    console.error("Admin get bookings error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin: Get all notifications
app.get("/admin/notifications", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ error: "Only admins can view all notifications" });
  }

  try {
    const notifications = await sql`
      SELECT n.*, u.name AS user_name, u.email AS user_email
      FROM notifications n
      JOIN users u ON n.user_id = u.id
      ORDER BY n.created_at DESC
    `;
    res.json(notifications);
  } catch (err) {
    console.error("Admin get notifications error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Global error:", err);
  res.status(500).json({ error: "Something went wrong!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
