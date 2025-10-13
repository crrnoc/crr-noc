require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require('bcrypt');
const PDFDocument = require('pdfkit');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');
const { spawn } = require('child_process');
const router = express.Router();
const adminRoutes = require("./admin");
const app = express();
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const PDFParser = require("pdf2json");
const pdfParse = require("pdf-parse");
const axios = require("axios");
const xmlbuilder = require('xmlbuilder');
const cloudinary = require("cloudinary").v2;
const csv = require("csv-parser");
const ExcelJS = require("exceljs");

// ✅ Inject Script middleware
function injectScript(filePath, res) {
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      console.error("❌ Error reading file:", filePath, err);
      return res.status(500).send("Server Error");
    }
    const modified = data.replace(
      /<\/body>/i,
      `<script src="/session.js"></script>\n</body>`
    );
    res.send(modified);
  });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

const logoBase64 = fs.readFileSync('./public/crrengglogo.png', { encoding: 'base64' });

// Configure the email transporter
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // use SSL
  auth: {
    user: "sircrrcoestd@sircrrengg.ac.in",
    pass: "eczr eaoo ruqa pwba",
  },
});


// ✅ Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 🔒 SESSION STORE
const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

// 🔐 Express-session config
app.use(session({
  key: 'noc_sid',
  secret: 'sircrrengg@123',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 15 * 60 * 1000, // 15 minutes
    httpOnly: true
  },
  rolling: true // reset expiry on each request
}));

// Prevent caching for protected routes
function noCache(req, res, next) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
}

// 🔐 Middleware to protect pages
function requireAdminSession(req, res, next) {
  const allowedRoles = [
    'admin', 'exam', 'hod', 'student', 'staff', 
    'correspondent', 'principal', 'mainaccounts', 'busaccounts', 'scholarships', 'hostelaccounts'
  ];

  if (req.session.userId && allowedRoles.includes(req.session.role)) {
    return next();
  }
  res.redirect('/index.html');
}


// ✅ Session check route
app.get('/check-session', noCache, (req, res) => {
  const allowedRoles = [
    'admin', 'exam', 'accounts', 'mainaccounts', 'busaccounts',
    'scholarships', 'hostel', 'hod', 'student', 'staff',
    'correspondent', 'principal'
  ];

  if (req.session.userId && allowedRoles.includes(req.session.role)) {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});


// ✅ Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('noc_sid', { path: '/' });
    res.redirect('/index.html');
  });
});

cloudinary.config({
  cloud_name: "dn1c2f2bg",
  api_key: "284748761934616",
  api_secret: "SJufb0jcVKNb3rAaTecC2aQPCH0"
});

// ✅ Static files
app.use(express.static(path.join(__dirname, "public")));

// ✅ Secure routes (all with injectScript)
app.get("/adminpanel", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "adminpanel.html"), res);
});
app.get("/uploadresults", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "uploadresultsAd.html"), res);
});
app.get("/uploadsbi", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "upload-sbi.html"), res);
});
app.get("/dumatch", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "du-match-status.html"), res);
});
app.get("/accountcopy", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "accountcopy.html"), res);
});
app.get("/uploadattendance", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "uploadattendanceAd.html"), res);
});
app.get("/nocstatus", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "noc-status.html"), res);
});
app.get("/removestudents", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "removestudents.html"), res);
});
app.get("/createnoc", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "createnocAd.html"), res);
});
app.get("/uploadfees", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "uploadstudentfee.html"), res);
});
app.get("/uploadstudents", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "uploadstudents.html"), res);
});
app.get("/uploadmidmarks", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "uploadmid-marks.html"), res);
});
app.get("/addmycounselling", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "addmycounselling.html"), res);
});
app.get("/examcell", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "examcell.html"), res);
});
app.get("/studentsfeesearch", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "studentsfeesearch.html"), res);
});
app.get("/staffallocation", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "staffallocation.html"), res);
});
app.get("/downloadattendance", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "downloadattendance.html"), res);
});
app.get("/editattendance", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "editattendance.html"), res);
});
app.get("/sendsms", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "sendsms.html"), res);
});
app.get("/addstident", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "addstudent.html"), res);
});
app.get("/correspondent-dashboard.html", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "correspondent-dashboard.html"), res);
});
app.get("/principal-dashboard.html", requireAdminSession, (req, res) => {
  injectScript(path.join(__dirname, "public", "principal-dashboard.html"), res);
});

app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // for previews

// ✅ Ensure uploads dir exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ✅ MySQL pool
const pool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.query((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.stack);
  } else {
    console.log('✅ Connected to MySQL database');
  }
});

// 🧹 Cleanup old notifications
setInterval(() => {
  const query = `DELETE FROM notifications WHERE date_sent < NOW() - INTERVAL 3 DAY`;
  pool.query(query, (err, result) => {
    if (err) {
      console.error("❌ Failed to delete old notifications:", err);
    } else {
      console.log(`🧹 Deleted ${result.affectedRows} notifications older than 3 days`);
    }
  });
}, 24 * 60 * 60 * 1000);

// ✅ Admin routes
app.use("/admin", adminRoutes);

// ✅ Login route - all (with Accounts subroles)
app.post('/login', (req, res) => {
  const { userId, password, role } = req.body;

  console.log(`[LOGIN ATTEMPT] ${new Date().toLocaleString()} | Role: ${role} | UserID: ${userId}`);

  pool.query(
    'SELECT * FROM users WHERE userId = ? AND role = ?',
    [userId, role],
    (err, results) => {
      if (err) {
        console.error("❌ DB Error during login:", err);
        return res.status(500).json({ success: false, message: 'Database error. Please try again.' });
      }

      if (results.length === 0) {
        return res.status(401).json({ success: false, message: 'Invalid credentials or role mismatch' });
      }

      const user = results[0];

      bcrypt.compare(password, user.password, (err2, isMatch) => {
        if (err2) {
          console.error("❌ Bcrypt error:", err2);
          return res.status(500).json({ success: false, message: 'Internal error during password check' });
        }

        if (!isMatch) {
          return res.status(401).json({ success: false, message: 'Incorrect password' });
        }

        // ✅ Save session
        req.session.userId = userId;
        req.session.role = role;

        // ✅ Update login counts
        pool.query(
          "INSERT INTO login_counts (role, count) VALUES (?, 1) ON DUPLICATE KEY UPDATE count = count + 1",
          [role],
          (err3) => {
            if (err3) {
              console.error("⚠️ Failed to update login count:", err3);
            }
          }
        );

        // ✅ Redirect mapping
        let redirectTo = "";

        if (role === "student") redirectTo = `/student/${userId}`;
        else if (role === "staff") redirectTo = `/staff/${userId}`;
        else if (role === "admin") redirectTo = `/adminpanel.html`;
        else if (role === "hod") redirectTo = `/hodpanel.html`;
        else if (role === "exam") redirectTo = `/examcell.html`;
        else if (role === "correspondent") redirectTo = `/correspondent-dashboard.html`;
        else if (role === "principal") redirectTo = `/principal-dashboard.html`;

        // ✅ Accounts Subroles
        else if (role === "mainaccounts") redirectTo = `/accountspanel.html`;
        else if (role === "busaccounts") redirectTo = `/accountspanel.html`;
        else if (role === "scholarships") redirectTo = `/accountspanel.html`;
        else if (role === "hostelaccounts") redirectTo = `/accounts-hostel.html`;

        // ✅ Send success response
        return res.status(200).json({
          success: true,
          message: 'Login successful',
          userId,
          role,
          redirectTo
        });
      });
    }
  );
});

// route for counts
// 📌 Route to get login counts
app.get("/api/login-counts", (req, res) => {
  const sql = "SELECT role, `count` FROM login_counts";

   pool.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error fetching login counts:", err);
      return res.status(500).json({ success: false, message: "DB Error" });
    }

    let studentCount = 0;
    let staffCount = 0;

    // Loop through DB results
    results.forEach(row => {
      if (row.role === "student") {
        studentCount = row.count; 
      } else if (["staff","admin","hod","exam","accounts","principal","correspondent"].includes(row.role)) {
        staffCount += row.count; 
      }
    });

    res.json({
      success: true,
      studentCount,
      staffCount
    });
  });
});

//email otp
// Store OTPs temporarily in memory (for demo purpose only)
const otpMap = new Map();

// 1️⃣ Send OTP
app.post('/send-otp', (req, res) => {
  const { userId, email } = req.body;

  // First try from students
  pool.query('SELECT email FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err) return res.json({ success: false, message: "Server error" });

    if (results.length > 0 && results[0].email === email) {
      return sendOtpToEmail(userId, email, res); // student match
    }

    // Try from staff
    pool.query('SELECT staff_email FROM staff WHERE staff_id = ?', [userId], (err2, results2) => {
      if (err2 || results2.length === 0 || results2[0].staff_email !== email) {
        return res.json({ success: false, message: "User ID and email don't match." });
      }

      // staff match
      return sendOtpToEmail(userId, email, res);
    });
  });
});

function sendOtpToEmail(userId, email, res) {
  const otp = Math.floor(100000 + Math.random() * 900000);
  otpMap.set(userId, otp.toString());

const mailOptions = {
  from: '"CRR Student Support Team" <sircrrcoestd@sircrrengg.ac.in>',
  to: email,
  subject: "Password Reset - One Time Password (OTP)",
  text: `Dear Student,

We have received a request to reset your account password.  
Please use the following One Time Password (OTP) to proceed:

OTP: ${otp}

This OTP is valid for 10 minutes only.  
If you did not request this, please ignore this email.

Best Regards,  
CRR Student Support Team
Sir C.R. Reddy College of Engineering
`,
};


  transporter.sendMail(mailOptions, (err) => {
    if (err) return res.json({ success: false, message: "Failed to send email." });

    setTimeout(() => otpMap.delete(userId), 10 * 60 * 1000); // expire OTP after 10 minutes
    res.json({ success: true });
  });
}


// 2️⃣ Verify OTP
app.post('/verify-otp', (req, res) => {
  const { userId, otp } = req.body;
  const storedOtp = otpMap.get(userId);
  if (storedOtp && storedOtp === otp) {
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});


// 3️⃣ Reset Password with hashing
app.post('/reset-password', async (req, res) => {
  const { userId, newPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    pool.query(
      'UPDATE users SET password = ? WHERE userId = ?',
      [hashedPassword, userId],
      (err, result) => {
        if (err || result.affectedRows === 0) {
          return res.json({ success: false, message: "User not found or update failed." });
        }

        otpMap.delete(userId);
        res.json({ success: true });
      }
    );
  } catch (error) {
    console.error("Hashing error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// 👤 Get student details
  app.get('/student/:userId', (req, res) => {
  const { userId } = req.params;

  pool.query('SELECT * FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    res.json(results[0]);
  });
});     


// ✏️ Update student profile
app.post("/editprofile", upload.single("photo"), async (req, res) => {
  const {
    userId,
    name,
    dob,
    reg_no,
    uniqueId,
    year,
    course,
    dept_code,
    semester,
    aadhar_no,
    mobile_no,
    email,
    father_name,
    father_mobile,
    admission_type,
    section,
    counsellor_name,
    counsellor_mobile
  } = req.body;

  const file = req.file;
  console.log("📥 Edit Profile Req:", req.body);

  try {
    let photo_url = null;
    let public_id = null;

    if (file) {
      const result = await cloudinary.uploader.upload(file.path, {
        public_id: `students/${reg_no}`,
        overwrite: true,
        resource_type: "image"
      });
      photo_url = result.secure_url;
      public_id = result.public_id;
      fs.unlinkSync(file.path);
    }

    const updateFields = [
      name,
      dob || null,
      reg_no,
      uniqueId,
      year,
      course,
      dept_code,
      semester,
      aadhar_no,
      mobile_no,
      email,
      father_name,
      father_mobile,
      admission_type,
      section,
      counsellor_name,
      counsellor_mobile
    ];

    let sql = `
      UPDATE students SET
        name=?,
        dob=?,
        reg_no=?,
        uniqueId=?,
        year=?,
        course=?,
        dept_code=?,
        semester=?,
        aadhar_no=?,
        mobile_no=?,
        email=?,
        father_name=?,
        father_mobile=?,
        admission_type=?,
        section=?,
        counsellor_name=?,
        counsellor_mobile=?`;

    if (photo_url) {
      sql += `, photo_url=?, photo_public_id=?`;
      updateFields.push(photo_url, public_id);
    }

    sql += ` WHERE userId=?`;
    updateFields.push(userId);

    pool.query(sql, updateFields, (err, result) => {
      if (err) {
        console.error("❌ SQL Error:", err);
        return res.status(500).json({ message: "Profile update failed" });
      }
      console.log("✅ Profile updated for:", userId);
      return res.status(200).json({ message: "Profile updated successfully!" });
    });

  } catch (err) {
    console.error("❌ Error:", err);
    if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    return res.status(500).json({ message: "Server error" });
  }
});


// 🚀 Start server (only once!)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


//message route for staff

app.post('/send-bulk-notification', async (req, res) => {
  let { userIds, message } = req.body;

  console.log("🔥 HIT /send-bulk-notification");
  console.log("👉 Request Body:", req.body);

  if (typeof userIds === 'string') userIds = [userIds];
  if (!Array.isArray(userIds) || userIds.length === 0 || !message) {
    console.log("❌ Invalid input");
    return res.status(400).json({ success: false, message: "Invalid input" });
  }

  let sent = 0;
  let failed = 0;

  for (const userId of userIds) {
    console.log("📦 Processing userId:", userId);
    await new Promise(resolve => {
      const query = 'SELECT email, name FROM students WHERE userId = ?';
      pool.query(query, [userId], (err, results) => {
        if (err || results.length === 0) {
          console.log("❌ Student not found or DB error for:", userId, err);
          failed++;
          return resolve();
        }

        const student = results[0];
        console.log("✅ Found student:", student.name, "📧", student.email);

const mailOptions = {
  from: '"CRR Student Support Team" <sircrrcoestd@sircrrengg.ac.in>',
  to: student.email,
  subject: "Official Notification - Sir C.R. Reddy College of Engineering",
  html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.6; color: #333;">
      <h2 style="color: #003366; margin-bottom: 10px;">Sir C.R. Reddy College of Engineering</h2>
      <hr style="border: none; border-top: 2px solid #003366; margin: 10px 0 20px 0;" />
      <p>Dear <strong>${student.name}</strong>,</p>
      <p>${message}</p>
      <br>
      <p style="color: #555; margin-top: 20px;">
        Best regards,<br>
        <strong>CRR Student Support Team</strong><br>
        Sir C.R. Reddy College of Engineering
      </p>
    </div>
  `
};

        transporter.sendMail(mailOptions, (err2) => {
          if (err2) {
            console.log("❌ Email sending failed to:", student.email, "Error:", err2.message);
          } else {
            console.log("📧 Email sent to:", student.email);
          }

          pool.query(
            'INSERT INTO notifications (userId, message) VALUES (?, ?)',
            [userId, message],
            (err3) => {
              if (err3) {
                console.log("❌ Notification insert failed for:", userId, err3.message);
                failed++;
              } else {
                console.log("✅ Notification saved for:", userId);
                sent++;
              }
              resolve();
            }
          );
        });
      });
    });
  }

  console.log("✅ Summary: Sent =", sent, "Failed =", failed);
  res.json({ success: true, sent, failed });
});

// Get notifications for a specific user
// GET: Notifications with staff name included
app.get('/notifications/:userId', (req, res) => {
  const { userId } = req.params;

  const query = `
    SELECT n.message, n.date_sent, s.staff_name
    FROM notifications n
    LEFT JOIN staff s ON n.staffId = s.staff_id
    WHERE n.userId = ?
    ORDER BY n.date_sent DESC
  `;

  pool.query(query, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching notifications:", err);
      return res.status(500).json({ success: false, message: "Error retrieving notifications" });
    }

    res.json({ success: true, notifications: results });
  });
});

//fine impose
// POST: Impose Fine and send notification
app.post('/impose-fine', (req, res) => {
  const { userId, amount, reason, staffId, academic_year } = req.body;

  if (!userId || !reason || !amount || !staffId || !academic_year) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  const fineQuery = `
    INSERT INTO fines (userId, amount, reason, staffId, academic_year)
    VALUES (?, ?, ?, ?, ?)
  `;
  const fineValues = [userId, amount, reason, staffId, academic_year];

  pool.query(fineQuery, fineValues, (err, result) => {
    if (err) {
      console.error("❌ Error inserting fine:", err);
      return res.status(500).json({ success: false, message: "Failed to insert fine" });
    }

    const message = `💸 Fine of ₹${amount} for Year ${academic_year}. Reason: ${reason}`;
    const notifyQuery = `
      INSERT INTO notifications (userId, message, staffId)
      VALUES (?, ?, ?)
    `;
    pool.query(notifyQuery, [userId, message, staffId], (err2) => {
      if (err2) {
        console.error("❌ Notification insert error:", err2);
        return res.status(500).json({ success: false, message: "Fine added, but notification failed" });
      }

      res.json({ success: true, message: "Fine imposed and student notified!" });
    });
  });
});


//total fine there exist before
app.get('/total-fine/:userId', (req, res) => {
  const { userId } = req.params;
  pool.query('SELECT SUM(amount) AS totalFine FROM fines WHERE userId = ?', [userId], (err, results) => {
    if (err) {
      console.error("Error fetching fine:", err);
      return res.status(500).json({ success: false });
    }
    res.json({ success: true, totalFine: results[0].totalFine || 0 });
  });
});

//fee detuction dynamically
// Get remaining fee for a student
router.get('/remaining-fee/:reg_no', async (req, res) => {
  const regNo = req.params.reg_no;

  try {
    // 1. Get original fee structure
    const [structureRows] = await pool.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ?',
      [regNo]
    );

    if (structureRows.length === 0) {
      return res.json({ success: false, message: "Fee structure not found." });
    }

    const structure = structureRows[0];

    // 2. Get total paid per category
    const [paidRows] = await pool.query(
      'SELECT fee_type, SUM(amount) AS paid FROM student_fee_payment WHERE reg_no = ? GROUP BY fee_type',
      [regNo]
    );

    const paidMap = {};
    paidRows.forEach(row => {
      paidMap[row.fee_type] = parseFloat(row.paid);
    });

    // 3. Calculate remaining fee
    const remaining = {
      tuition: (structure.tuition || 0) - (paidMap.tuition || 0),
      hostel: (structure.hostel || 0) - (paidMap.hostel || 0),
      bus: (structure.bus || 0) - (paidMap.bus || 0),
      university: (structure.university || 0) - (paidMap.university || 0),
      semester: (structure.semester || 0) - (paidMap.semester || 0),
      library: (structure.library || 0) - (paidMap.library || 0),
      fines: (structure.fines || 0) - (paidMap.fines || 0),
    };

    res.json({ success: true, data: remaining });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

//paid amounts
app.get('/paid-amounts/:userId', (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT fee_type, SUM(amount_paid) AS paid 
    FROM student_fee_payments 
    WHERE userId = ? AND matched = 1 
    GROUP BY fee_type
  `;

  pool.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Paid amounts fetch error:", err);
      return res.status(500).json([]);
    }

    res.json(results);
  });
});

//reference number submission
app.post("/submit-du", (req, res) => {
  const { userId, payments, academic_year } = req.body;

  if (!userId || !Array.isArray(payments) || !academic_year) {
    return res.status(400).json({ success: false, message: "Invalid data" });
  }

  // 🧠 Step 1: Get unique_id from students table
  pool.query(
    "SELECT uniqueId FROM students WHERE userId = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("❌ Error fetching unique_id:", err);
        return res.status(500).json({ success: false, message: "Server error" });
      }

      if (!results.length || !results[0].uniqueId) {
        return res.status(400).json({
          success: false,
          message: "❌ Unique ID missing. Please update your profile first."
        });
      }

      const unique_id = results[0].uniqueId;
      const values = [];
      const checkMatches = [];
      const duChecks = [];

      // 📦 Loop through payments
      for (const p of payments) {
        const du = p.du?.trim();
        const amt = parseFloat(p.amount);
        const feeType = p.type;

        if (!du || isNaN(amt) || !feeType) continue;

        // ✅ Prepare values for matching
        values.push([userId, unique_id, feeType, du, amt, academic_year, 0]);

        // 🧠 Check if DU + amount exists in SBI uploaded table
        checkMatches.push(
          new Promise(resolve => {
            pool.query(
              "SELECT * FROM sbi_uploaded_references WHERE sbi_ref_no = ? AND amount = ? AND unique_id = ?",
              [du, amt, unique_id],
              (err, results) => {
                if (err) return resolve([du, false]);
                resolve([du, results.length > 0]);
              }
            );
          })
        );

        // 🧠 Check if DU already exists anywhere in student_fee_payments
        duChecks.push(
          new Promise((resolve, reject) => {
            pool.query(
              `SELECT userId, unique_id, academic_year, fee_type 
               FROM student_fee_payments 
               WHERE sbi_ref_no = ?`,
              [du],
              (err, results) => {
                if (err) return reject(err);
                if (results.length > 0) {
                  return reject({
                    message: `❌ Reference Number ${du} already exists for User: ${results[0].userId}, UniqueId: ${results[0].unique_id}, Year: ${results[0].academic_year}, Fee: ${results[0].fee_type}`
                  });
                }
                resolve();
              }
            );
          })
        );
      }

      // 🔁 First check duplicates
      Promise.all(duChecks)
        .then(() => {
          // 🔁 After all matches
          Promise.all(checkMatches).then(matchResults => {
            const matchMap = Object.fromEntries(matchResults);

            // 🔄 Build final values with matched = 1 or 0
            const finalValues = values.map(([userId, unique_id, type, du, amt, year, matched]) => {
              const isMatched = matchMap[du] ? 1 : 0;
              return [userId, unique_id, type, du, amt, year, isMatched];
            });

            const sql = `
              INSERT INTO student_fee_payments (
                userId, unique_id, fee_type, sbi_ref_no, amount_paid, academic_year, matched
              )
              VALUES ?
              ON DUPLICATE KEY UPDATE
                sbi_ref_no = VALUES(sbi_ref_no),
                amount_paid = VALUES(amount_paid),
                matched = VALUES(matched),
                academic_year = VALUES(academic_year),
                unique_id = VALUES(unique_id),
                matched_on = IF(matched = 0 AND VALUES(matched) = 1, NOW(), matched_on)
            `;

            pool.query(sql, [finalValues], (err2) => {
              if (err2) {
                console.error("❌ Insert error:", err2);
                return res.status(500).json({ success: false, message: "DB error" });
              }

              res.json({
                success: true,
                message: "✅ DU entries submitted and matched successfully."
              });
            });
          });
        })
        .catch(err => {
          return res.status(400).json({
            success: false,
            message: err.message || "❌ Duplicate Reference Number found."
          });
        });
    }
  );
});

//fee structure
app.get("/fee-structure/:reg_no", (req, res) => {
  const reg_no = req.params.reg_no;

  const sql = `
    SELECT * FROM student_fee_structure 
    WHERE reg_no = ? 
    ORDER BY updated_at DESC 
    LIMIT 1
  `;

  pool.query(sql, [reg_no], (err, results) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "No fee structure found." });
    }
    res.json({ success: true, data: results[0] });
  });
});

app.get('/noc-eligibility/:userId', (req, res) => {
  const { userId } = req.params;

  pool.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(500).json({ success: false });
    }

    const reg_no = studentRows[0].reg_no;

    // 1. Get latest fee structure
    pool.query(`
      SELECT * FROM student_fee_structure 
      WHERE reg_no = ? 
      ORDER BY updated_at DESC 
      LIMIT 1
    `, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) {
        return res.status(400).json({ success: false, message: 'Fee structure not found' });
      }

      const feeStructure = feeRows[0];

      // 2. Get paid amounts from student_fee_payment
      pool.query(`
        SELECT fee_type, SUM(amount) AS paid 
        FROM student_fee_payment 
        WHERE reg_no = ? 
        GROUP BY fee_type
      `, [reg_no], (err3, paidRows) => {
        if (err3) return res.status(500).json({ success: false });

        const paidMap = {};
        paidRows.forEach(row => {
          paidMap[row.fee_type] = parseFloat(row.paid);
        });

        // 3. Final check: compare each component
        const expected = {
          tuition: parseFloat(feeStructure.tuition) || 0,
          hostel: parseFloat(feeStructure.hostel) || 0,
          bus: parseFloat(feeStructure.bus) || 0,
          university: parseFloat(feeStructure.university) || 0,
          semester: parseFloat(feeStructure.semester) || 0,
          library: parseFloat(feeStructure.library) || 0,
          fines: parseFloat(feeStructure.fines) || 0
        };

        for (const key in expected) {
          const paid = paidMap[key] || 0;
          const remaining = expected[key] - paid;
          if (remaining > 0) {
            return res.json({ success: true, eligible: false });
          }
        }

        // ✅ All paid
        res.json({ success: true, eligible: true });
      });
    });
  });
});

//upload sbi data

app.post('/admin/upload-sbi', upload.single('sbiFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: '❌ No file uploaded.' });
  }

  const userRole = req.session.role; // ✅ detect who logged in
  console.log(`📂 SBI Upload Attempt by role: ${userRole}`);

  const filePath = path.join(__dirname, req.file.path);
  const results = [];
  const csv = require('csv-parser');
  const fs = require('fs');

  // ✅ Allowed fees based on role
  const allowedFeeTypes = {
    mainaccounts: ["Tuition Fee Payable", "University Other Fee Payable"],
    busaccounts: ["Bus Fee Payable"],
    scholarships: ["Scholarship Fee Payable"], // future extension
    hostel: ["Hostel Fee Payable"]             // future extension
  };

  fs.createReadStream(filePath)
    .pipe(csv())
    .on('data', (row) => {
      const du = row["Bank Reference No"]?.trim();
      const amt = parseFloat(row["Amount"]);
      const status = row["Status"]?.toLowerCase();
      const uniqueId = row["UNIQUE NO"]?.trim();

      let txnDate = row["Transaction Date"]?.trim() || null;

      // Detect fee type
      let feetype = null;
      if (row["Tuition Fee Payable"] && parseFloat(row["Tuition Fee Payable"]) > 0) {
        feetype = "Tuition Fee Payable";
      } else if (row["University Other Fee payable"] && parseFloat(row["University Other Fee payable"]) > 0) {
        feetype = "University Other Fee Payable";
      } else if (row["Bus Fee Payable"] && parseFloat(row["Bus Fee Payable"]) > 0) {
        feetype = "Bus Fee Payable";
      } else if (row["Examination Fee Payable"] && parseFloat(row["Examination Fee Payable"]) > 0) {
        feetype = "Examination Fee Payable";
      } else if (row["Earlier Dues If any Payable"] && parseFloat(row["Earlier Dues If any Payable"]) > 0) {
        feetype = "Earlier Dues Payable";
      } else {
        feetype = "Unknown";
      }

      // ✅ Filter by role: only push if role allows this feetype
      if (
        du && amt && uniqueId && status &&
        status.includes("completed successfully") &&
        allowedFeeTypes[userRole]?.includes(feetype)
      ) {
        results.push([du, amt, uniqueId, feetype, txnDate]);
      }
    })
    .on('end', () => {
      if (results.length === 0) {
        return res.status(400).json({ 
          success: false, 
          message: `❌ No valid COMPLETED entries found for role ${userRole}.`
        });
      }

      const insertQuery = `
        INSERT INTO sbi_uploaded_references 
          (sbi_ref_no, amount, unique_id, feetype, transaction_date)
        VALUES ?
        ON DUPLICATE KEY UPDATE 
          amount = VALUES(amount), 
          unique_id = VALUES(unique_id),
          feetype = VALUES(feetype),
          transaction_date = VALUES(transaction_date)
      `;

      pool.query(insertQuery, [results], (err) => {
        if (err) {
          console.error('❌ Upload error:', err);
          return res.status(500).json({ success: false, message: 'Upload failed.' });
        }

        const matchQuery = `
          UPDATE student_fee_payments p
          JOIN students s ON p.userId = s.userId
          JOIN sbi_uploaded_references r 
            ON p.sbi_ref_no = r.sbi_ref_no 
            AND p.amount_paid = r.amount 
            AND s.uniqueId = r.unique_id
          SET 
            p.matched = 1, 
            p.matched_on = NOW(), 
            p.feetype = r.feetype, 
            p.txn_date = r.transaction_date
          WHERE p.matched = 0
        `;

        pool.query(matchQuery, (err2, result) => {
          if (err2) {
            console.error('❌ Match error:', err2);
            return res.status(500).json({ success: false, message: 'Matching failed.' });
          }

          res.json({ 
            success: true, 
            message: `✅ SBI file uploaded successfully by ${userRole}. ${result.affectedRows} entries matched.` 
          });
        });
      });
    })
    .on('error', (err) => {
      console.error('❌ CSV parsing error:', err);
      res.status(500).json({ success: false, message: 'Failed to parse CSV.' });
    });
});


// ✅ Matches (recent uploads & matches)
// ✅ Fetch all SBI uploaded entries (direct payments)
app.get('/admin/matches', (req, res) => {
  const sql = `
    SELECT 
      s.name,
      s.reg_no AS userId,
      r.feetype,
      r.amount,
      r.sbi_ref_no,
      DATE_FORMAT(r.uploaded_on, '%d-%m-%Y') AS uploaded_on,
      r.transaction_date
    FROM sbi_uploaded_references r
    JOIN students s ON r.unique_id = s.uniqueId
    ORDER BY r.uploaded_on DESC
  `;

  pool.query(sql, (err, results) => {
    if (err) {
      console.error('❌ Error fetching matches:', err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});


// ✅ Search NOC status by reg_no / name / userId
app.post('/admin/search-noc-status', (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ success: false, message: "No query provided" });

  const searchTerm = `%${query}%`;
  const sql = `
    SELECT userId, reg_no, name, uniqueId 
    FROM students 
    WHERE userId LIKE ? OR name LIKE ? OR reg_no LIKE ?
  `;

  pool.query(sql, [searchTerm, searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error("❌ Search error:", err);
      return res.status(500).json({ success: false });
    }

    const checks = results.map(student => {
      const { userId, reg_no, name, uniqueId } = student;

      return new Promise(resolve => {
        // ✅ Get total paid fees directly from SBI uploads
        pool.query(
          `SELECT feetype, SUM(amount) AS totalPaid
           FROM sbi_uploaded_references 
           WHERE unique_id = ? 
           GROUP BY feetype`,
          [uniqueId],
          (err2, paidRows) => {
            if (err2) return resolve({ userId, name, eligible: false });

            const paidMap = {};
            paidRows.forEach(r => paidMap[r.feetype] = parseFloat(r.totalPaid));

            // ✅ Get latest expected fee structure
            pool.query(
              `SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1`,
              [reg_no],
              (err3, feeRows) => {
                if (err3 || feeRows.length === 0) return resolve({ userId, name, eligible: false });

                const fees = feeRows[0];

                // ✅ Get fines
                pool.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    // ✅ Compare expected vs paid
                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };

                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, name, eligible: false });
                    }

                    resolve({ userId, name, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });

    Promise.all(checks).then(data => res.json({ success: true, data }));
  });
});


// ✅ Get NOC status for ALL students
app.get('/admin/noc-status', (req, res) => {
  pool.query('SELECT userId, reg_no, uniqueId FROM students', (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no, uniqueId } = student;

      return new Promise(resolve => {
        // ✅ Latest expected structure
        pool.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, eligible: false });

            const fees = feeRows[0];

            // ✅ Paid fees (direct from uploads)
            pool.query(
              `SELECT feetype, SUM(amount) AS totalPaid 
               FROM sbi_uploaded_references 
               WHERE unique_id = ? 
               GROUP BY feetype`,
              [uniqueId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.feetype] = parseFloat(r.totalPaid));

                pool.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };

                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, eligible: false });
                    }

                    resolve({ userId, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });

    Promise.all(checks).then(data => res.json(data));
  });
});

//logic for the fee status for qr code
// ===============================
// Get Fee Status by UserId
// ===============================
app.get("/fee-status/:userId", async (req, res) => {
  const { userId } = req.params;

  const typeMap = {
    "tuition fee": "tuition", "tuition": "tuition", "tuition fee payable": "tuition",
    "hostel fee": "hostel", "hostel": "hostel", "hostel fee payable": "hostel",
    "bus fee": "bus", "bus": "bus", "bus fee payable": "bus",
    "university fee": "university", "university": "university",
    "university fee payable": "university", "university other fee payable": "university",
    "semester fee": "semester", "semester": "semester", "semester fee payable": "semester",
    "library dues": "library", "library": "library", "library fee": "library", "library dues payable": "library",
    "fine": "fines", "fines": "fines"
  };

  try {
    // Fetch student info
    const [studentRows] = await pool.promise().query(
      "SELECT reg_no, uniqueId FROM students WHERE userId = ?",
      [userId]
    );
    if (!studentRows.length) 
      return res.status(404).json({ success: false, message: "Student not found" });

    const { reg_no, uniqueId } = studentRows[0];

    // Fetch fee structure
    const [feeRows] = await pool.promise().query(
      "SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC",
      [reg_no]
    );
    if (!feeRows.length) 
      return res.status(404).json({ success: false, message: "No fee structure found" });

    // Fetch payments
    const [payments] = await pool.promise().query(
      "SELECT feetype, amount FROM sbi_uploaded_references WHERE unique_id = ?",
      [uniqueId]
    );

    // Prepare payment pool
    const paymentPool = { tuition: 0, hostel: 0, bus: 0, university: 0, semester: 0, library: 0, fines: 0 };
    payments.forEach(p => {
      const key = p.feetype?.toLowerCase().trim();
      const type = typeMap[key];
      if (type) paymentPool[type] += parseFloat(p.amount || 0);
    });

    const finalYears = {};
    let carryForwardDue = 0;

    // Calculate yearly fees
    for (const fee of feeRows) {
      const year = fee.academic_year;

      const expected = {
        tuition: parseFloat(fee.tuition) || 0,
        hostel: parseFloat(fee.hostel) || 0,
        bus: parseFloat(fee.bus) || 0,
        university: parseFloat(fee.university) || 0,
        semester: parseFloat(fee.semester) || 0,
        library: parseFloat(fee.library) || 0,
        fines: parseFloat(fee.fines) || 0
      };

      const paid = {};
      const due = {};

      for (const type of Object.keys(expected)) {
        const need = expected[type];
        const available = paymentPool[type] || 0;
        const applied = Math.min(available, need);

        paid[type] = applied;
        due[type] = need - applied;

        paymentPool[type] -= applied;
      }

      const expectedTotal = Object.values(expected).reduce((a, b) => a + b, 0);
      const paidTotal = Object.values(paid).reduce((a, b) => a + b, 0);
      const thisYearDue = Object.values(due).reduce((a, b) => a + b, 0);

      // Include previous year's due
      const totalDue = thisYearDue + carryForwardDue;

      // Update carry forward
      carryForwardDue = totalDue;

      finalYears[year] = {
        expected,
        paid,
        due,
        expectedTotal,
        paidTotal,
        totalDue
      };
    }

    return res.json({ success: true, userId, reg_no, years: finalYears });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});




app.post("/add-student", async (req, res) => {
  const {
    userId, name, dob, reg_no, unique_id,
    year, course, semester, aadhar_no, mobile_no,
    email = "", password, section,
    father_name, father_mobile_no,
    counsellor_name, counsellor_mobile,
    admission_type 
  } = req.body;

  // Required fields for validation
  const must = {
    userId, reg_no, unique_id, year, course,
    semester, section, password,
    counsellor_name, counsellor_mobile
  };

  for (const k in must) {
    if (!must[k] && must[k] !== "") {
      return res.status(400).json({ success: false, message: `Missing: ${k}` });
    }
  }

  try {
    //  Capitalize helper
    const capitalize = (s) =>
      (s || "").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());

    const studentName = capitalize(name);
    const fatherName = capitalize(father_name);
    const counsellorName = capitalize(counsellor_name);
    const sectionUpper = (section || "").toUpperCase();

    // Check if user already exists
    pool.query("SELECT 1 FROM users WHERE userid = ?", [userId], async (e, r) => {
      if (e) return res.status(500).json({ success: false });
      if (r.length) return res.status(400).json({ success: false, message: "User exists" });

      const hashed = await bcrypt.hash(password, 10);

      //  Insert into users table
      pool.query(
        "INSERT INTO users (userid, password, role) VALUES (?, ?, 'student')",
        [userId, hashed],
        (e1) => {
          if (e1) return res.status(500).json({ success: false, message: "User insert failed" });

          //  Insert into students table with admission_type
          const studentSql = `
            INSERT INTO students
              (userId, reg_no, uniqueId, year, course, semester, section,
               counsellor_name, counsellor_mobile,
               name, dob, aadhar_no, mobile_no, email,
               father_name, father_mobile, admission_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          `;

          const vals = [
            userId, reg_no, unique_id, year, course, semester, sectionUpper,
            counsellorName, counsellor_mobile,
            studentName || null, dob || null, aadhar_no || null, mobile_no || null, email,
            fatherName || null, father_mobile_no || null,
            admission_type || null
          ];

          pool.query(studentSql, vals, (e2) => {
            if (e2) {
              console.error("Student insert error:", e2);
              return res.status(500).json({ success: false });
            }
            res.json({ success: true });
          });
        }
      );
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

//logic for the fee upadate by staff
//Staff updates fee structure for a student by reg_no
app.post('/update-fee-structure', (req, res) => {
  const {
    reg_no, academic_year, tuition, hostel, bus,
    university, semester, library, fines
  } = req.body;

  if (!reg_no || !academic_year) {
    return res.status(400).json({ success: false, message: "Reg No and Year required" });
  }

  const queryCheck = `
    SELECT * FROM student_fee_structure 
    WHERE reg_no = ? AND academic_year = ?
  `;

  pool.query(queryCheck, [reg_no, academic_year], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "DB error" });

  const sql = result.length > 0
  ? `UPDATE student_fee_structure SET
      tuition=?, hostel=?, bus=?, university=?, semester=?, \`library\`=?, fines=?, updated_at=NOW()
     WHERE reg_no=? AND academic_year=?`
  : `INSERT INTO student_fee_structure 
     (reg_no, academic_year, tuition, hostel, bus, university, semester, \`library\`, fines, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`;


    const values = result.length > 0
      ? [tuition, hostel, bus, university, semester, library, fines, reg_no, academic_year]
      : [reg_no, academic_year, tuition, hostel, bus, university, semester, library, fines];

   pool.query(sql, values, (err2) => {
  if (err2) {
    console.error("❌ Fee update query failed:", err2.message); // this logs the actual MySQL error
    return res.status(500).json({ success: false, message: "Query failed", error: err2.message });
  }

  res.json({ success: true, message: "✅ Year-wise fee updated successfully!" });
});

  });
});

//noc pdf code
// ... all previous code remains unchanged
//Updated Generate NOC PDF logic (fixed hanging issue)
app.get('/generate-noc/:userId', (req, res) => {
  const { userId } = req.params;
  const academicYear = parseInt(req.query.year);

  if (!academicYear || academicYear < 1 || academicYear > 4) {
    return res.status(400).json({ success: false, message: 'Invalid or missing year' });
  }

  // 1️⃣ Fetch student details
  pool.query(
    'SELECT name, course, reg_no, uniqueId FROM students WHERE userId = ?',
    [userId],
    (err, studentRows) => {
      if (err || studentRows.length === 0) {
        return res.status(404).json({ success: false, message: 'Student not found' });
      }

      const student = studentRows[0];
      const { reg_no, uniqueId } = student;

      // 2️⃣ Fetch yearwise fee structure
      pool.query(
        'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
        [reg_no],
        (err2, feeRows) => {
          if (err2 || feeRows.length === 0) {
            return res.status(404).json({ success: false, message: 'No fee data' });
          }

          // 3️⃣ Fetch all payments
          pool.query(
            'SELECT feetype, amount, uploaded_on FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC',
            [uniqueId],
            (err3, payments) => {
              if (err3) {
                return res.status(500).json({ success: false, message: 'Payments fetch error' });
              }

              // Map fee types
              const typeMap = {
                'tuition fee payable': 'tuition', 'tuition fee': 'tuition', tuition: 'tuition',
                'hostel fee payable': 'hostel', 'hostel fee': 'hostel', hostel: 'hostel',
                'bus fee payable': 'bus', 'bus fee': 'bus', bus: 'bus',
                'university fee payable': 'university', 'university other fee payable': 'university', 'university fee': 'university', university: 'university',
                'semester fee payable': 'semester', 'semester fee': 'semester', semester: 'semester',
                'library dues payable': 'library', 'library dues': 'library', library: 'library',
                fine: 'fines', fines: 'fines'
              };

              // Payment pool
              const paymentPool = {
                tuition: 0, hostel: 0, bus: 0, university: 0,
                semester: 0, library: 0, fines: 0
              };

              payments.forEach(p => {
                const type = typeMap[p.feetype?.toLowerCase()];
                if (!type) return;
                paymentPool[type] += parseFloat(p.amount || 0);
              });

              // 4️⃣ Recalculate yearwise
              let carryForwardDue = 0;
              let yearData = null;

              for (const fee of feeRows) {
                const year = fee.academic_year;

                const expected = {
                  tuition: parseFloat(fee.tuition) || 0,
                  hostel: parseFloat(fee.hostel) || 0,
                  bus: parseFloat(fee.bus) || 0,
                  university: parseFloat(fee.university) || 0,
                  semester: parseFloat(fee.semester) || 0,
                  library: parseFloat(fee.library) || 0,
                  fines: parseFloat(fee.fines) || 0
                };

                const paid = {};
                const due = {};

                for (const type of Object.keys(expected)) {
                  const need = expected[type];
                  const available = paymentPool[type] || 0;
                  const apply = Math.min(available, need);

                  paid[type] = apply;
                  due[type] = need - apply;

                  paymentPool[type] -= apply;
                }

                const expectedTotal = Object.values(expected).reduce((a, b) => a + b, 0);
                const paidTotal = Object.values(paid).reduce((a, b) => a + b, 0);
                const totalDue = Object.values(due).reduce((a, b) => a + b, 0) + carryForwardDue;

                carryForwardDue = totalDue;

                if (year === academicYear) {
                  yearData = { year, expected, paid, due, expectedTotal, paidTotal, totalDue };
                  break;
                }
              }

              if (!yearData) {
                return res.status(404).json({ success: false, message: 'No fee structure for that year' });
              }

              // 5️⃣ Generate PDF
              const fileName = `noc_${userId}_year${academicYear}.pdf`;
              const filePath = path.join(__dirname, 'uploads', fileName);
              const doc = new PDFDocument({ margin: 50 });
              const stream = fs.createWriteStream(filePath);
              doc.pipe(stream);

              // Header
              const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
              if (fs.existsSync(headerPath)) {
                doc.image(headerPath, { fit: [500, 150], align: 'center' });
                doc.moveDown(3);
              }

              doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE', { align: 'center', underline: true });
              doc.moveDown(1.5);

              doc.font('Times-Bold').fontSize(12).text(
                `This is to certify that Mr./Ms. ${student.name} (Roll No: ${student.reg_no}),`,
                { align: 'justify' }
              );
              doc.moveDown(0.5);
              doc.font('Times-Roman').text(
                `A bonafide student of ${student.course}, has the following fee details towards the institution for Year ${academicYear}.`,
                { align: 'justify' }
              );
              doc.moveDown(1);

              doc.font('Times-Bold').fontSize(13).text("FEE DETAILS", { align: 'center', underline: true });
              doc.moveDown();

              const readableMap = {
                tuition: "TUTION FEE", hostel: "HOSTEL FEE", bus: "BUS FEE",
                university: "UNIVERSITY FEE", semester: "EXAM CELL",
                library: "LIBRARY DUES", fines: "FINES"
              };

              const tableLeftX = 70;
              const tableRightX = 380;
              const rowHeight = 20;
              let y = doc.y;

              Object.keys(yearData.expected).forEach(type => {
                const remaining = yearData.due[type];
                const status = remaining <= 0 ? "PAID ✅" : `DUE ₹${remaining}`;
                doc.text(readableMap[type], tableLeftX, y);
                doc.text(status, tableRightX, y);
                y += rowHeight;
              });

              doc.moveDown();
              doc.text("This is a system-generated certificate and does not require a manual signature.", { align: 'center' });
              doc.moveDown(1);
              doc.font('Times-Bold').text("COLLEGE STAMP", { align: 'center' });

              // QR
              const qrLink = `https://crr-noc.onrender.com/verifybyqr.html?userId=${userId}&year=${academicYear}`;
              QRCode.toDataURL(qrLink, (err, qrUrl) => {
                if (!err) {
                  const qrSize = 50;
                  const qrX = 150;
                  const qrY = doc.page.height - qrSize - 150;

                  doc.image(qrUrl, qrX, qrY, { width: qrSize });
                  doc.font('Times-Roman')
                    .fontSize(10)
                    .text('Scan to verify the NOC', qrX - 10, qrY + qrSize + 5, {
                      width: qrSize + 30,
                      align: 'center'
                    });
                }

                // Footer
                const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
                if (fs.existsSync(footerPath)) {
                  doc.image(footerPath, (doc.page.width - 500) / 2, doc.page.height - 100, { width: 500 });
                }

                doc.end();

                stream.on("finish", () => {
                  res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
                  res.setHeader("Content-Type", "application/pdf");
                  fs.createReadStream(filePath).pipe(res);
                });
              });
            }
          );
        }
      );
    }
  );
});

//logic for combined-noc
app.get('/generate-combined-noc/:userId', (req, res) => {
  const { userId } = req.params;

  pool.query('SELECT name, course, reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    const student = studentRows[0];
    const reg_no = student.reg_no;

    pool.query(`SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC`, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) {
        return res.status(400).json({ success: false, message: 'No fee structure found' });
      }

      const promises = feeRows.map(fee => {
        const year = fee.academic_year;

        return new Promise(resolve => {
          pool.query(
            `SELECT fee_type, SUM(amount_paid) AS paid 
             FROM student_fee_payments 
             WHERE userId = ? AND matched = 1 AND academic_year = ?
             GROUP BY fee_type`,
            [userId, year],
            (err3, paidRows) => {
              const paidMap = {};
              paidRows?.forEach(row => paidMap[row.fee_type] = parseFloat(row.paid));

              pool.query(
                'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
                [userId, year],
                (err4, fineRes) => {
                  const fineAmount = parseFloat(fineRes[0]?.fine || 0);

                  const expected = {
                    tuition: parseFloat(fee.tuition || 0),
                    hostel: parseFloat(fee.hostel || 0),
                    bus: parseFloat(fee.bus || 0),
                    university: parseFloat(fee.university || 0),
                    semester: parseFloat(fee.semester || 0),
                    library: parseFloat(fee.library || 0),
                    fines: fineAmount
                  };

                  let allPaid = true;
                  for (const key in expected) {
                    const paid = paidMap[key] || 0;
                    const remaining = expected[key] - paid;
                    if (remaining > 0) {
                      allPaid = false;
                      break;
                    }
                  }

                  resolve({ year, status: allPaid ? "✅ Paid" : "❌ Not Paid" });
                }
              );
            }
          );
        });
      });

      Promise.all(promises).then(yearStatuses => {
        const fileName = `combined_noc_${userId}.pdf`;
        const filePath = path.join(__dirname, 'uploads', fileName);
        const doc = new PDFDocument({ margin: 50 });
        const stream = fs.createWriteStream(filePath);
        doc.pipe(stream);

        // Header
        const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
        if (fs.existsSync(headerPath)) {
          doc.image(headerPath, { fit: [500, 150], align: 'center' });
          doc.moveDown(2);
        }

        // Title
        doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE – FEE STATUS (ALL YEARS)', {
          align: 'center',
          underline: true
        });
        doc.moveDown();

        // Professional body
        doc.font('Times-Roman').fontSize(12).text(
          `This is to formally certify that Mr./Ms. ${student.name} (Reg. No: ${reg_no}), currently enrolled in the ${student.course} program at our institution, has completed the prescribed fee payments as per the academic requirements. The year-wise fee payment status is verified from official records and is provided below:`,
          { align: 'justify' }
        );
        doc.moveDown();

        doc.font('Times-Roman').fontSize(12).text(
          `This certificate is being issued upon the request of the student for the purpose of submission to external academic institutions, internship providers, employers, or any other authorities where official confirmation of fee clearance is required.`,
          { align: 'justify' }
        );
        doc.moveDown();

        // Year-wise status list
        yearStatuses.forEach(({ year, status }) => {
          doc.font('Times-Bold').fontSize(13).text(`${year} Year: ${status}`);
        });

        doc.moveDown(2);
        doc.font('Times-Italic').fontSize(11).text(
          "This certificate has been digitally generated and does not require a physical signature. It is valid for all official and academic purposes.",
          { align: 'center' }
        );

        doc.moveDown();
        doc.font('Times-Roman').fontSize(11).text(
          `This certificate remains valid unless found altered or tampered with. Verification can be performed using the QR code provided below.`,
          { align: 'center' }
        );

        doc.moveDown(2);
        doc.font('Times-Roman').text("Authorized By", { align: 'right' });
        doc.font('Times-Italic').text("Head of Accounts Department", { align: 'right' });

        // QR Code
        const qrLink = `https://crr-noc.onrender.com/verifybyqr.html?userId=${userId}&combined=true`;

        QRCode.toDataURL(qrLink, (err, qrUrl) => {
          if (!err && qrUrl) {
            doc.image(qrUrl, 250, doc.y + 10, { width: 60 });
          }

          // Footer
          const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
          if (fs.existsSync(footerPath)) {
            doc.image(footerPath, (doc.page.width - 500) / 2, doc.page.height - 100, { width: 500 });
          }

          doc.end();
          stream.on("finish", () => {
            res.download(filePath, fileName);
          });
        });
      });
    });
  });
});
//year wise fee verification
app.get('/verify-yearwise-noc/:userId/:year', async (req, res) => {
  const { userId, year } = req.params;

  try {
    // 1️⃣ Get student details
    const [studentRows] = await pool.promise().query(
      'SELECT reg_no, uniqueId FROM students WHERE userId = ?',
      [userId]
    );

    if (studentRows.length === 0)
      return res.json({ success: false, message: 'Student not found' });

    const { reg_no, uniqueId } = studentRows[0];

    // 2️⃣ Fetch all fee rows for this student
    const [feeRows] = await pool.promise().query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no]
    );

    if (feeRows.length === 0)
      return res.json({ success: false, message: 'No fee structure found' });

    // 3️⃣ Fetch all payments
    const [payments] = await pool.promise().query(
      'SELECT feetype, amount FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC',
      [uniqueId]
    );

    // 4️⃣ Normalize feetype
    const typeMap = {
      'tuition fee payable': 'tuition', 'tuition fee': 'tuition', tuition: 'tuition',
      'hostel fee payable': 'hostel', 'hostel fee': 'hostel', hostel: 'hostel',
      'bus fee payable': 'bus', 'bus fee': 'bus', bus: 'bus',
      'university fee payable': 'university', 'university other fee payable': 'university',
      'university fee': 'university', university: 'university',
      'semester fee payable': 'semester', 'semester fee': 'semester', semester: 'semester',
      'library dues payable': 'library', 'library dues': 'library', library: 'library',
      fine: 'fines', fines: 'fines'
    };

    const paymentPool = { tuition:0, hostel:0, bus:0, university:0, semester:0, library:0, fines:0 };
    payments.forEach(p => {
      const type = typeMap[p.feetype?.toLowerCase()];
      if (!type) return;
      paymentPool[type] += parseFloat(p.amount || 0);
    });

    let carryForwardDue = 0;
    let yearFound = false;
    let resultPaid = {}, resultDue = {}, expected = {};

    // 5️⃣ Apply payments year by year until we reach the requested year
    for (const fee of feeRows) {
      const y = fee.academic_year;

      // Expected fees for this year
      expected = {
        tuition: parseFloat(fee.tuition) || 0,
        hostel: parseFloat(fee.hostel) || 0,
        bus: parseFloat(fee.bus) || 0,
        university: parseFloat(fee.university) || 0,
        semester: parseFloat(fee.semester) || 0,
        library: parseFloat(fee.library) || 0,
        fines: parseFloat(fee.fines) || 0
      };

      resultPaid = {};
      resultDue = {};

      for (const type of Object.keys(expected)) {
        const need = expected[type];
        const available = paymentPool[type] || 0;
        const apply = Math.min(available, need);

        resultPaid[type] = apply;
        resultDue[type] = need - apply;

        paymentPool[type] -= apply;
      }

      const totalDue = Object.values(resultDue).reduce((a, b) => a + b, 0) + carryForwardDue;
      carryForwardDue = totalDue;

      if (y.toString() === year.toString()) {
        yearFound = true;
        break; // Stop once we reach the requested year
      }
    }

    if (!yearFound)
      return res.json({ success: false, message: 'Year not found in fee data' });

    const totalDue = Object.values(resultDue).reduce((a, b) => a + b, 0) + carryForwardDue;
    const eligible = totalDue === 0;

    res.json({
      success: true,
      reg_no,
      year,
      eligible,
      expected,
      paid: resultPaid,
      due: resultDue,
      totalDue
    });

  } catch (err) {
    console.error("❌ verify-yearwise-noc error:", err);
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// logic for the combined noc verification by qr
app.get('/verify-combined-noc/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // 1️⃣ Get student reg_no and uniqueId
    const [studentRows] = await pool.promise().query(
      'SELECT reg_no, uniqueId FROM students WHERE userId = ?',
      [userId]
    );

    if (studentRows.length === 0)
      return res.json({ success: false, message: 'Student not found' });

    const { reg_no, uniqueId } = studentRows[0];

    // 2️⃣ Fetch fee structure
    const [feeRows] = await pool.promise().query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no]
    );

    if (feeRows.length === 0)
      return res.json({ success: false, message: 'No fee structure found' });

    // 3️⃣ Fetch all payments
    const [payments] = await pool.promise().query(
      'SELECT feetype, amount FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC',
      [uniqueId]
    );

    // normalize feetype
    const typeMap = {
      'tuition fee payable': 'tuition', 'tuition fee': 'tuition', tuition: 'tuition',
      'hostel fee payable': 'hostel', 'hostel fee': 'hostel', hostel: 'hostel',
      'bus fee payable': 'bus', 'bus fee': 'bus', bus: 'bus',
      'university fee payable': 'university', 'university other fee payable': 'university',
      'university fee': 'university', university: 'university',
      'semester fee payable': 'semester', 'semester fee': 'semester', semester: 'semester',
      'library dues payable': 'library', 'library dues': 'library', library: 'library',
      fine: 'fines', fines: 'fines'
    };

    const paymentPool = {
      tuition: 0, hostel: 0, bus: 0, university: 0, semester: 0, library: 0, fines: 0
    };

    payments.forEach(p => {
      const type = typeMap[p.feetype?.toLowerCase()];
      if (!type) return;
      paymentPool[type] += parseFloat(p.amount || 0);
    });

    let carryForwardDue = 0;
    const yearStatuses = [];

    for (const fee of feeRows) {
      const year = fee.academic_year;

      const expected = {
        tuition: parseFloat(fee.tuition) || 0,
        hostel: parseFloat(fee.hostel) || 0,
        bus: parseFloat(fee.bus) || 0,
        university: parseFloat(fee.university) || 0,
        semester: parseFloat(fee.semester) || 0,
        library: parseFloat(fee.library) || 0,
        fines: parseFloat(fee.fines) || 0
      };

      const resultPaid = {};
      const resultDue = {};

      for (const type of Object.keys(expected)) {
        const need = expected[type];
        const available = paymentPool[type] || 0;
        const apply = Math.min(available, need);

        resultPaid[type] = apply;
        resultDue[type] = need - apply;

        paymentPool[type] -= apply;
      }

      const totalDue = Object.values(resultDue).reduce((a, b) => a + b, 0) + carryForwardDue;
      carryForwardDue = totalDue;

      yearStatuses.push({
        year,
        status: totalDue > 0 ? "❌ Not Paid" : "✅ Paid",
        totalDue
      });
    }

    const eligible = yearStatuses.every(y => y.status === "✅ Paid");

    res.json({
      success: true,
      reg_no,
      eligible,
      yearStatuses
    });

  } catch (err) {
    console.error("❌ verify-combined-noc error:", err);
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});



app.post('/api/submit-feedback', (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  // HTML Email for User
const userMailOptions = {
  from: '"CRR Student Support Team" <sircrrcoestd@sircrrengg.ac.in>',
  to: email,
  subject: "Acknowledgment of Your Feedback - Sir C.R. Reddy College of Engineering",
  html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; line-height: 1.6; color: #333;">
      <h2 style="color:#003366; margin-top: 0;">Sir C.R. Reddy College of Engineering</h2>
      <hr style="border: none; border-top: 2px solid #003366; margin: 10px 0 20px 0;" />
      <p>Dear <strong>${name}</strong>,</p>
      <p>Thank you for sharing your feedback with us. We truly value the time you took to provide your thoughts and suggestions. Our team will carefully review your message and take necessary actions, if required.</p>
      <p><strong>Your submitted message:</strong></p>
      <blockquote style="color: #555; font-style: italic; border-left: 4px solid #003366; padding-left: 10px; margin: 10px 0;">
        ${message}
      </blockquote>
      <p style="margin-top: 20px; color: #555;">
        Best regards,<br>
        <strong>CRR Student Support Team</strong><br>
        Sir C.R. Reddy College of Engineering
      </p>
    </div>
  `
};
  // Email to Admin
  const adminMailOptions = {
  from: '"CRR STD Bot" <sircrrcoestd@sircrrengg.ac.in>',
  to: 'sircrrcoestd@sircrrengg.ac.in',
  subject: `Feedback Received from ${name}`,
  html: `
    <div style="font-family: Arial; padding: 20px;">
      <h2 style="color:#003366;">Sir C R Reddy College of Engineering</h2>
      <h3 style="color: #222;">New Feedback Received</h3>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Message:</strong><br>${message}</p>
      <p style="color: #888; font-size: 13px;">Timestamp: ${new Date().toLocaleString()}</p>
    </div>
  `
};
  // Send both emails
  transporter.sendMail(userMailOptions, (err1) => {
    if (err1) {
      console.error("User email error:", err1);
      return res.status(500).json({ success: false, message: "Failed to notify user." });
    }
    transporter.sendMail(adminMailOptions, (err2) => {
      if (err2) {
        console.error("Admin email error:", err2);
        return res.status(500).json({ success: false, message: "Failed to notify admin." });
      }
      res.status(200).json({ success: true, message: "Feedback submitted successfully!" });
    });
  });
});

app.get('/student-du-entries/:userId', (req, res) => {
  const { userId } = req.params;

  const sql = `
    SELECT id, fee_type, sbi_ref_no, amount_paid, matched, created_at 
    FROM student_fee_payments 
    WHERE userId = ? 
    ORDER BY created_at DESC
  `;

  pool.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching DU entries:", err);
      return res.status(500).json([]);
    }

    res.json(results);
  });
});
// 🧾 Get all fee entries for a user from sbi_uploaded_references table
app.get("/my-fee-entries/:userId", (req, res) => {
  const { userId } = req.params;
  
  const sql = `
    SELECT 
      sur.id,
      sur.feetype AS fee_type,
      sur.amount AS amount_paid,
      sur.sbi_ref_no,
      sur.uploaded_on AS created_at,
      sur.transaction_date,
      sur.status,
      1 AS matched  -- All entries are verified since they're from sbi_uploaded_references
    FROM students s
    INNER JOIN sbi_uploaded_references sur 
      ON s.uniqueId = sur.unique_id
    WHERE s.userId = ?
    ORDER BY sur.uploaded_on DESC
  `;

  pool.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Fetch error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

// Note: Delete route is no longer needed since all payments are verified

app.post('/admin/search-student-sbi', (req, res) => {
  const { query } = req.body;

  if (!query || query.trim() === "") {
    return res.status(400).json({ success: false, message: "Query is required" });
  }

  const likeQuery = `%${query.toLowerCase()}%`;
  
  const sql = `
    SELECT 
      s.reg_no AS userId,
      s.name AS studentName,
      f.fee_type,
      f.sbi_ref_no,
      f.amount_paid,
      f.matched AS fee_matched,
      f.matched_on AS fee_matched_on,
      f.academic_year
    FROM students s
    LEFT JOIN student_fee_payments f ON s.reg_no = f.userId
    WHERE LOWER(s.reg_no) LIKE ? OR LOWER(s.name) LIKE ?
    ORDER BY f.matched_on DESC
  `;

  pool.query(sql, [likeQuery, likeQuery], (err, results) => {
    if (err) {
      console.error("🔥 SQL Execution Error:", err.sqlMessage);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }

    res.json({ success: true, data: results });
  });
});


app.get('/admin/noc-status', (req, res) => {
  pool.query('SELECT userId, reg_no, name FROM students', (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no, name } = student;

      return new Promise(resolve => {
        // 1️ Get latest fee structure
        pool.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, name, eligible: false });

            const fees = feeRows[0];

            // 2️Get verified paid fees
            pool.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 
               GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, name, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));

                // Get fines
                pool.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
                  [userId],
                  (err4, fineRes) => {
                    const fine = err4 ? 0 : (fineRes[0]?.fine || 0);

                    const expected = {
                      tuition: parseFloat(fees.tuition) || 0,
                      hostel: parseFloat(fees.hostel) || 0,
                      bus: parseFloat(fees.bus) || 0,
                      university: parseFloat(fees.university) || 0,
                      semester: parseFloat(fees.semester) || 0,
                      library: parseFloat(fees.library) || 0,
                      fines: parseFloat(fine)
                    };

                    for (let key in expected) {
                      const remaining = expected[key] - (paidMap[key] || 0);
                      if (remaining > 0) return resolve({ userId, name, eligible: false });
                    }

                    resolve({ userId, name, eligible: true });
                  }
                );
              }
            );
          }
        );
      });
    });

    Promise.all(checks).then(data => res.json(data));
  });
});


// ===============================
// HOD Year-wise Fee Route
// ===============================
app.get('/hod/yearwise-fee/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // 1️⃣ Get student info
    const [studentRows] = await pool.promise().query(
      'SELECT reg_no, uniqueId FROM students WHERE userId = ?',
      [userId]
    );
    if (studentRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }
    const { reg_no, uniqueId } = studentRows[0];

    // 2️⃣ Get student fee structure (year-wise)
    const [feeRows] = await pool.promise().query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no]
    );
    if (feeRows.length === 0) {
      return res.status(404).json({ success: false, message: 'No fee data' });
    }

    // 3️⃣ Get payments made by student
    const [payments] = await pool.promise().query(
      'SELECT feetype, amount, uploaded_on FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC',
      [uniqueId]
    );

    // 🔹 Map fee types
    const typeMap = {
      'tuition fee payable': 'tuition', 'tuition fee': 'tuition', tuition: 'tuition',
      'hostel fee payable': 'hostel', 'hostel fee': 'hostel', hostel: 'hostel',
      'bus fee payable': 'bus', 'bus fee': 'bus', bus: 'bus',
      'university fee payable': 'university', 'university other fee payable': 'university',
      'university fee': 'university', university: 'university',
      'semester fee payable': 'semester', 'semester fee': 'semester', semester: 'semester',
      'library dues payable': 'library', 'library dues': 'library', library: 'library',
      fine: 'fines', fines: 'fines'
    };

    // 🔹 Pool of available payments
    const paymentPool = {
      tuition: 0, hostel: 0, bus: 0, university: 0, semester: 0, library: 0, fines: 0
    };

    payments.forEach(p => {
      const type = typeMap[p.feetype?.toLowerCase()];
      if (type) paymentPool[type] += parseFloat(p.amount || 0);
    });

    let carryForwardDue = 0; // only total due carried forward
    const finalData = [];

    for (const fee of feeRows) {
      const year = fee.academic_year;

      // Expected fee for the year
      const expected = {
        tuition: parseFloat(fee.tuition) || 0,
        hostel: parseFloat(fee.hostel) || 0,
        bus: parseFloat(fee.bus) || 0,
        university: parseFloat(fee.university) || 0,
        semester: parseFloat(fee.semester) || 0,
        library: parseFloat(fee.library) || 0,
        fines: parseFloat(fee.fines) || 0
      };

      const paid = {};
      const due = {};

      // Apply payments for each type
      for (const type of Object.keys(expected)) {
        const need = expected[type];
        const available = paymentPool[type] || 0;
        const applied = Math.min(available, need);

        paid[type] = applied;
        due[type] = need - applied;

        paymentPool[type] -= applied; // reduce available balance
      }

      const expectedTotal = Object.values(expected).reduce((a, b) => a + b, 0);
      const paidTotal = Object.values(paid).reduce((a, b) => a + b, 0);

      // Due for this year only
      const thisYearDue = Object.values(due).reduce((a, b) => a + b, 0);

      // 🔹 Add carry forward from previous years
      const totalDue = thisYearDue + carryForwardDue;

      // Update carry forward for next loop
      carryForwardDue = totalDue;

      finalData.push({
        academicYear: year,
        expected,
        paid,
        due,
        expectedTotal,
        paidTotal,
        thisYearDue,
        carryForwardFromPrev: carryForwardDue - thisYearDue,
        totalDue
      });
    }

    res.json({ success: true, data: finalData });
  } catch (err) {
    console.error("❌ Error in HOD yearwise-fee route:", err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

//student fee detials
app.get('/yearwise-fee/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // 1️⃣ Get student reg_no and uniqueId
    const [studentRows] = await pool.promise().query(
      'SELECT reg_no, uniqueId FROM students WHERE userId = ?',
      [userId]
    );

    if (studentRows.length === 0)
      return res.status(404).json({ success: false, message: 'Student not found' });

    const { reg_no, uniqueId } = studentRows[0];

    // 2️⃣ Fetch fee structure ordered by academic year
    const [feeRows] = await pool.promise().query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no]
    );

    if (feeRows.length === 0)
      return res.status(404).json({ success: false, message: 'No fee data' });

    // 3️⃣ Fetch all payments ordered by transaction date
    const [payments] = await pool.promise().query(
      'SELECT feetype, amount, uploaded_on FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC',
      [uniqueId]
    );

    // Map feetype variations to internal keys
    const typeMap = {
      'tuition fee payable': 'tuition', 'tuition fee': 'tuition', tuition: 'tuition',
      'hostel fee payable': 'hostel', 'hostel fee': 'hostel', hostel: 'hostel',
      'bus fee payable': 'bus', 'bus fee': 'bus', bus: 'bus',
      'university fee payable': 'university', 'university other fee payable': 'university', 'university fee': 'university', university: 'university',
      'semester fee payable': 'semester', 'semester fee': 'semester', semester: 'semester',
      'library dues payable': 'library', 'library dues': 'library', library: 'library',
      fine: 'fines', fines: 'fines'
    };

    // Initialize payment pool per type
    const paymentPool = {
      tuition: 0, hostel: 0, bus: 0, university: 0, semester: 0, library: 0, fines: 0
    };

    payments.forEach(p => {
      const type = typeMap[p.feetype?.toLowerCase()];
      if (!type) return;
      paymentPool[type] += parseFloat(p.amount || 0);
    });

    const finalData = [];
    let carryForwardDue = 0; // 🆕 Only total due carry forward

    for (const fee of feeRows) {
      const year = fee.academic_year;

      // Expected fees
      const expected = {
        tuition: parseFloat(fee.tuition) || 0,
        hostel: parseFloat(fee.hostel) || 0,
        bus: parseFloat(fee.bus) || 0,
        university: parseFloat(fee.university) || 0,
        semester: parseFloat(fee.semester) || 0,
        library: parseFloat(fee.library) || 0,
        fines: parseFloat(fee.fines) || 0
      };

      const resultPaid = {};
      const resultDue = {};

      // Apply payments from pool
      for (const type of Object.keys(expected)) {
        const need = expected[type];
        const available = paymentPool[type] || 0;
        const apply = Math.min(available, need);

        resultPaid[type] = apply;
        resultDue[type] = need - apply;

        paymentPool[type] -= apply;
      }

      const expectedTotal = Object.values(expected).reduce((a, b) => a + b, 0);
      const paidTotal = Object.values(resultPaid).reduce((a, b) => a + b, 0);
      const totalDue = Object.values(resultDue).reduce((a, b) => a + b, 0) + carryForwardDue;

      // Update carryForwardDue for next year
      carryForwardDue = totalDue;

      finalData.push({
        year,
        expected,
        paid: resultPaid,
        due: resultDue,
        expectedTotal,
        paidTotal,
        totalDue
      });
    }

    res.json({ success: true, data: finalData });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});     


// view backlogs 
app.get("/total-backlogs", (req, res) => {
  const { regno } = req.query;
  if (!regno) {
    return res.status(400).json({ message: "Regno is required" });
  }

  // Decide which table to use
  const useRegularTable = ["20B8", "21B8", "22B8", "23B8", "24B85A"].some(prefix =>
    regno.toUpperCase().startsWith(prefix)
  );
  const tableName = useRegularTable ? "results" : "autonomous_results";

  const query = `SELECT semester, subcode, grade, subname FROM ${tableName} WHERE regno = ?`;
  pool.query(query, [regno], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching data", error: err });
    }

    // Normalize grade → uppercase + trim
    const normalizeGrade = g => (g || "").trim().toUpperCase();

    // Backlog conditions
    const isBacklog = g =>
      ["F", "AB", "ABSENT", "MP", "NOT CO", "NOTCOMPLETED"].includes(normalizeGrade(g));

    const backlogData = results.filter(r => isBacklog(r.grade));

    res.json({
      backlogData,
      count: backlogData.length
    });
  });
});

// get Student Details for Removal
app.post("/get-student-details", async (req, res) => {
  const { reg_no } = req.body;
  try {
    const [rows] = await connection.promise().query("SELECT * FROM students WHERE reg_no = ?", [reg_no]);
    if (rows.length === 0) {
      return res.json({ success: false, message: "Student not found" });
    }
    res.json({ success: true, student: rows[0] });
  } catch (err) {
    console.error("Fetch error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Delete Student with Photo Removal
// Delete a single student and all their data
app.post('/delete-student', (req, res) => {
  const { reg_no } = req.body;

  if (!reg_no) return res.status(400).json({ success: false, message: "Registration number required." });

  // Step 1: get the matching userId from students
  pool.query('SELECT userId FROM students WHERE reg_no = ?', [reg_no], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found." });
    }

    const userId = results[0].userId;

    // Step 2: delete from all relevant tables using correct keys
    const queries = [
      ['DELETE FROM students WHERE reg_no = ?', [reg_no]],
      ['DELETE FROM users WHERE userid = ?', [userId]], // ✅ fixed
      ['DELETE FROM student_fee_structure WHERE reg_no = ?', [reg_no]],
      ['DELETE FROM student_fee_payments WHERE userId = ?', [userId]],
      ['DELETE FROM notifications WHERE userId = ?', [userId]],
      ['DELETE FROM fines WHERE userId = ?', [userId]],
    ];

    let completed = 0;
    queries.forEach(([query, params]) => {
      pool.query(query, params, (err2) => {
        if (err2) console.error(`Error deleting from table: ${query}`, err2);
        completed++;
        if (completed === queries.length) {
          return res.json({ success: true, message: `Student ${reg_no} and all related data deleted.` });
        }
      });
    });
  });
});


// Filter Batch
app.post("/filter-batch", async (req, res) => {
  const { batchPrefix, branch } = req.body;
  try {
    const [students] = await connection.promise().query(
      "SELECT reg_no, name FROM students WHERE reg_no LIKE ? AND course = ?",
      [`${batchPrefix}%`, branch]
    );
    res.json({ success: true, students });
  } catch (err) {
    console.error("Batch filter error:", err);
    res.status(500).json({ success: false, students: [] });
  }
});

// Delete Batch
app.post('/delete-batch', (req, res) => {
  const { batchPrefix, branch } = req.body;

  if (!batchPrefix || !branch) {
    return res.status(400).json({ success: false, message: "Batch prefix and branch are required." });
  }

  const sql = `SELECT reg_no, userId FROM students WHERE reg_no LIKE ? AND branch = ?`;
  const likePrefix = `${batchPrefix}%`;

  pool.query(sql, [likePrefix, branch], (err, students) => {
    if (err || students.length === 0) {
      return res.status(404).json({ success: false, message: "No matching students found." });
    }

    let completed = 0;
    const total = students.length;

    students.forEach(({ reg_no, userId }) => {
      const queries = [
        ['DELETE FROM students WHERE reg_no = ?', [reg_no]],
        ['DELETE FROM users WHERE userid = ?', [userId]],
        ['DELETE FROM student_fee_structure WHERE reg_no = ?', [reg_no]],
        ['DELETE FROM student_fee_payments WHERE userId = ?', [userId]],
        ['DELETE FROM notifications WHERE userId = ?', [userId]],
        ['DELETE FROM fines WHERE userId = ?', [userId]],
      ];

      let subCompleted = 0;
      queries.forEach(([q, p]) => {
        pool.query(q, p, (err2) => {
          if (err2) console.error(`Error deleting: ${q}`, err2);
          subCompleted++;
          if (subCompleted === queries.length) {
            completed++;
            if (completed === total) {
              return res.json({ success: true, message: `Batch ${batchPrefix} - ${branch} students deleted.` });
            }
          }
        });
      });
    });
  });
});

// result pdf upload
// Admin uploads result PDF
app.post('/upload', upload.single('pdf'), (req, res) => {
  const semester = req.body.semester;
  const filePath = req.file?.path;

  console.log("📥 Semester:", semester);
  if (!semester || !filePath) {
    return res.status(400).json({ message: '❌ Semester or PDF missing.' });
  }

  console.log("📄 PDF File Path:", filePath);
  console.log("🐍 Running Python script...");

  const python = spawn('python3', ['extract_pdf.py', filePath, semester]);

  let output = '';
  let errorOutput = '';

  python.stdout.on('data', (data) => {
    output += data.toString();
  });

  python.stderr.on('data', (data) => {
    errorOutput += data.toString();
  });

  python.on('close', (code) => {
    console.log("🐍 Python exited with code:", code);
    if (errorOutput) console.error("🐍 stderr:\n", errorOutput);

    if (code !== 0) {
      return res.status(500).json({
        message: '❌ Upload failed: Python script error',
        error: errorOutput || 'Unknown error'
      });
    }

    let results;
    try {
      results = JSON.parse(output);
    } catch (jsonErr) {
      console.error("❌ JSON Parse Error:", jsonErr.message);
      console.error("📦 Raw output:\n", output);
      return res.status(500).json({
        message: '❌ Invalid JSON from Python',
        error: jsonErr.message
      });
    }

    if (!results.length) {
      return res.status(200).json({
        message: '✅ PDF processed but no records found.',
        total: 0
      });
    }

    // Insert all entries with UPSERT (ON DUPLICATE KEY UPDATE)
    let completed = 0;
    const total = results.length;

    results.forEach(({ regno, subcode, subname, grade, credits }) => {
      pool.query(
        `INSERT INTO results (regno, subcode, subname, grade, credits, semester)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           grade = VALUES(grade),
           credits = VALUES(credits),
           semester = VALUES(semester)`,
        [regno, subcode, subname, grade, credits, semester],
        (err) => {
          if (err) {
            console.error(`❌ Insert failed: ${regno} - ${subcode} ➜`, err.message);
          } else {
            console.log(`✅ Inserted/Updated: ${regno} - ${subcode}`);
          }

          completed++;
          if (completed === total) {
            res.status(200).json({
              message: '✅ PDF processed and records inserted/updated.',
              total,
              semester
            });
          }
        }
      );
    });
  });
});
// Upload route
// 📌 Upload Autonomous Results PDF - Fully Optimized
app.post("/admin/upload-autonomous-result-pdf", upload.single("pdf"), async (req, res) => {
  try {
    const { semester } = req.body;
    if (!req.file || !semester) {
      return res.status(400).json({ success: false, message: "❌ PDF and semester required." });
    }

    const { spawn } = require("child_process");
    const python = process.platform === "win32" ? "python" : "python3";

    const py = spawn(python, [
      "extract_pdf_results.py",
      "--input", req.file.path,
      "--semester", semester
    ]);

    let dataBuffer = "";
    py.stdout.on("data", chunk => dataBuffer += chunk.toString());
    py.stderr.on("data", err => console.error("🐍 Python error:", err.toString()));

    py.on("close", async code => {
      try {
        if (code !== 0) {
          return res.status(500).json({ success: false, message: "❌ Python script failed." });
        }

        const records = JSON.parse(dataBuffer);
        let inserted = 0;

        // ✅ Valid grades mapping
        const VALID_GRADES = {
          "S": "S",
          "A": "A",
          "B": "B",
          "C": "C",
          "D": "D",
          "E": "E",
          "F": "F",
          "AB": "Ab",
          "ABSENT": "Ab",
          "-AB-": "-Ab-",
          "COMPLETED": "Completed"
        };

        // ✅ Group records by student
        const studentsMap = {};
        records.forEach(rec => {
          const reg = rec.regno.trim();
          if (!studentsMap[reg]) studentsMap[reg] = [];
          studentsMap[reg].push(rec);
        });

        // ✅ Process each student separately
        for (const regno of Object.keys(studentsMap)) {
          const studentRecords = studentsMap[regno];
          const newSgpa = parseFloat(studentRecords[0].sgpa);

          let updatedSubjects = 0;

          // ✅ Prepare sanitized values
          const values = studentRecords
            .map(r => {
              let gradeRaw = (r.grade || "").trim().toUpperCase();

              // ❌ Skip empty / '-' / '--' → don't overwrite existing grades
              if (gradeRaw === "-" || gradeRaw === "--" || gradeRaw === "") {
                console.log(`⏩ Skipping ${r.subcode} for ${r.regno} → No grade in PDF`);
                return null;
              }

              // ✅ Normalize grade
              let grade = VALID_GRADES[gradeRaw] || gradeRaw;

              // ❌ If grade is unknown → skip subject
              if (!Object.values(VALID_GRADES).includes(grade)) {
                console.warn(`⚠ Unknown grade "${r.grade}" for ${r.regno} → Skipping ${r.subcode}`);
                return null;
              }

              updatedSubjects++;
              return [
                r.regno.trim(),
                semester.trim(),
                r.subcode.trim(),
                r.subname.trim(),
                grade,
                parseFloat(r.sgpa)
              ];
            })
            .filter(Boolean); // ✅ Remove skipped subjects

          // ❌ If no valid subjects, don't update DB or SGPA
          if (values.length === 0) {
            console.log(`⚠ No valid subjects for ${regno} → SGPA not updated`);
            continue;
          }

          // ✅ Build placeholders & values
          const placeholders = values.map(() => "(?, ?, ?, ?, ?, ?)").join(", ");
          const flatValues = values.flat();

          // ✅ Insert or update grades safely
          await new Promise(resolve => {
            pool.query(
              `
              INSERT INTO autonomous_results (regno, semester, subcode, subname, grade, sgpa)
              VALUES ${placeholders}
              ON DUPLICATE KEY UPDATE
                grade = VALUES(grade),
                subname = VALUES(subname),
                sgpa = VALUES(sgpa)
              `,
              flatValues,
              err => {
                if (err) {
                  console.error(`❌ DB Error [${regno}]:`, err.message);
                } else {
                  inserted += updatedSubjects;
                  console.log(`✅ Updated ${updatedSubjects} subjects for ${regno}`);
                }
                resolve();
              }
            );
          });

          // ✅ Update SGPA only if at least one subject was updated
          if (updatedSubjects > 0) {
            await new Promise(resolve => {
              pool.query(
                "UPDATE autonomous_results SET sgpa = ? WHERE regno = ? AND semester = ?",
                [newSgpa, regno, semester],
                err => {
                  if (err) console.error(`❌ Failed updating SGPA [${regno}]:`, err.message);
                  else console.log(`✅ SGPA updated for ${regno} - Sem ${semester}`);
                  resolve();
                }
              );
            });
          }
        }

        // ✅ Delete uploaded file after processing
        fs.unlinkSync(req.file.path);

        res.json({
          success: true,
          message: `✅ ${inserted} subject results inserted/updated successfully.`,
        });
      } catch (err) {
        console.error("❌ Fatal Error:", err);
        res.status(500).json({ success: false, message: "❌ Failed to process parsed data." });
      }
    });
  } catch (err) {
    console.error("❌ Server Error:", err);
    res.status(500).json({ success: false, message: "❌ Server error during parsing." });
  }
});

// Route: Upload attendance (PDF / Excel)
app.post("/upload-attendance", upload.single("file"), (req, res) => {
  const semester = req.body.semester;
  const filePath = req.file?.path;
  const fileExt = path.extname(req.file.originalname).toLowerCase();

  if (!semester || !filePath) {
    return res.status(400).json({ message: "❌ Semester or file missing." });
  }

  // ✅ Validate file type
  const allowedExts = [".pdf", ".xlsx", ".xls"];
  if (!allowedExts.includes(fileExt)) {
    return res.status(400).json({ message: "❌ Invalid file type. Please upload PDF or Excel only." });
  }

  console.log("📄 Attendance File Path:", filePath);
  console.log("📂 File Extension:", fileExt);
  console.log("🐍 Running Python attendance script...");

  // ✅ Run Python script
  const python = spawn("python", ["extract_attendance.py", filePath, semester, fileExt]);

  let output = "";
  let errorOutput = "";

  python.stdout.on("data", (data) => output += data.toString());
  python.stderr.on("data", (data) => errorOutput += data.toString());

  python.on("close", (code) => {
    console.log("🐍 Python exited with code:", code);
    if (errorOutput) console.error("🐍 stderr:\n", errorOutput);

    if (code !== 0) {
      return res.status(500).json({
        message: "❌ Python error",
        error: errorOutput || "Unknown error"
      });
    }

    let records;
    try {
      records = JSON.parse(output); // ✅ percentage preserved exactly as string from Python
    } catch (err) {
      return res.status(500).json({ message: "❌ Invalid JSON", error: err.message });
    }

    if (!records.length) {
      return res.status(400).json({ message: "❌ No attendance records found in file." });
    }

    let inserted = 0;
    const insertPromises = records.map(([regno, sem, total, present, percent]) => {
      return new Promise((resolve) => {
        pool.query(
          `INSERT INTO attendance 
           (regno, semester, total_classes, attended_classes, percentage) 
           VALUES (?, ?, ?, ?, ?) 
           ON DUPLICATE KEY UPDATE 
           total_classes=?, attended_classes=?, percentage=?`,
          [regno, sem, total, present, percent, total, present, percent],
          (err) => {
            if (err) console.error(`❌ DB Error for ${regno}:`, err.message);
            else inserted++;
            resolve();
          }
        );
      });
    });

    Promise.all(insertPromises).then(() => {
      const excelFileName = path.basename(filePath).replace(fileExt, ".xlsx");
      res.status(200).json({
        message: "✅ Attendance extracted and stored successfully.",
        total: inserted,
        excel_file: `/uploads/${excelFileName}`
      });
    }).catch((err) => {
      res.status(500).json({ message: "❌ DB insert failed", error: err.message });
    });
  });
});

app.get("/student-attendance/:regno", (req, res) => {
  const regno = req.params.regno;

  pool.query(
    "SELECT semester, total_classes, attended_classes, percentage FROM attendance WHERE regno = ? ORDER BY semester",
    [regno],
    (err, results) => {
      if (err) {
        console.error("DB error:", err);
        return res.status(500).json({ success: false, message: "Database error." });
      }

      res.json({ success: true, data: results });
    }
  );
});

const GRADE_POINTS = {
  S: 10,
  "A+": 10, // ✅ Added A+ grade
  A: 9,
  B: 8,
  C: 7,
  D: 6,
  E: 5,
  F: 0,
  Ab: 0,
  Absent: 0,
  Completed: 10
};

// 🟢 Common GPA + Percentage calculation
function calculateGPA(results) {
  let totalCredits = 0;
  let weightedSum = 0;

  for (const r of results) {
    const point = GRADE_POINTS[r.grade];
    if (point === undefined) continue;

    // ✅ If credits missing/null/undefined → assume 3
    const credits = r.credits ? r.credits : 3;

    weightedSum += point * credits;
    totalCredits += credits;
  }

  const gpa = totalCredits > 0 ? weightedSum / totalCredits : 0;

  // ✅ Official JNTU formula
  const percentage = totalCredits > 0 ? ((gpa - 0.75) * 10).toFixed(2) : "0.00";

  return { gpa: gpa.toFixed(2), percentage };
}

// ----------------- Semester-wise results -----------------
app.get('/student/results/:regno', async (req, res) => {
  const { regno } = req.params;
  const semester = req.query.semester;

  console.log("📥 Incoming Request:", { regno, semester });

  try {
    // 🔹 Fetch semester-wise results (normal + autonomous)
    pool.query(
      `
      SELECT subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [regno, semester, regno, semester],
      (err, semResults) => {
        if (err) {
          console.error("❌ Error fetching sem results:", err);
          return res.status(500).json({ error: "DB error (semResults)" });
        }

        // 🔹 Fetch overall results (normal + autonomous)
        pool.query(
          `
          SELECT grade, credits 
          FROM results 
          WHERE regno = ?

          UNION ALL

          SELECT sgpa as grade, NULL as credits 
          FROM autonomous_results 
          WHERE regno = ?
          `,
          [regno, regno],
          (err, allResults) => {
            if (err) {
              console.error("❌ Error fetching all results:", err);
              return res.status(500).json({ error: "DB error (allResults)" });
            }

            // ✅ Semester GPA Calculation:
            // If autonomous semester → directly fetch SGPA from table instead of calculating
            let semGPA = null;
            let semPercentage = null;

            const autonomousSemQuery = `
              SELECT sgpa 
              FROM autonomous_results 
              WHERE regno = ? AND semester = ?
              LIMIT 1
            `;

            pool.query(autonomousSemQuery, [regno, semester], (err, autoSem) => {
              if (err) {
                console.error("❌ Error fetching autonomous SGPA:", err);
                return res.status(500).json({ error: "DB error (autoSGPA)" });
              }

              if (autoSem.length > 0 && autoSem[0].sgpa !== null) {
                // Autonomous → use stored SGPA directly
                semGPA = autoSem[0].sgpa.toFixed(2);
                semPercentage = (semGPA * 10).toFixed(2);
              } else {
                // Non-autonomous → calculate SGPA
                const semCalc = calculateGPA(semResults);
                semGPA = semCalc.gpa;
                semPercentage = semCalc.percentage;
              }

              // ✅ Overall CGPA & Percentage calculation:
              // If autonomous results exist, use their SGPA directly.
              let totalSGPA = 0;
              let count = 0;

              // Sum up SGPA for autonomous results
              pool.query(
                `SELECT sgpa FROM autonomous_results WHERE regno = ? AND sgpa IS NOT NULL`,
                [regno],
                (err, autoRows) => {
                  if (err) {
                    console.error("❌ Error fetching autonomous CGPA data:", err);
                    return res.status(500).json({ error: "DB error (autoCGPA)" });
                  }

                  autoRows.forEach(row => {
                    totalSGPA += row.sgpa;
                    count++;
                  });

                  // For normal results → calculate from grades
                  const normalResults = allResults.filter(r => r.credits !== null);
                  if (normalResults.length > 0) {
                    const normalCalc = calculateGPA(normalResults);
                    totalSGPA += parseFloat(normalCalc.gpa) * normalResults.length;
                    count += normalResults.length;
                  }

                  const cgpa = count > 0 ? (totalSGPA / count).toFixed(2) : "0.00";
                  const overallPercentage = (cgpa * 10).toFixed(2);

                  res.json({
                    regno,
                    semester,
                    results: semResults,
                    sgpa: semGPA,
                    semPercentage,
                    cgpa,
                    overallPercentage
                  });
                }
              );
            });
          }
        );
      }
    );
  } catch (err) {
    console.error("❌ Uncaught Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// Updated Backend Route - Complete Precision Fix
app.get("/student/overallResults/:regno", async (req, res) => {
  const { regno } = req.params;

  try {
    // 1️⃣ Fetch all results (regular + autonomous)
    const [rows] = await pool.promise().query(
      `
      SELECT grade, credits 
      FROM results 
      WHERE regno = ?

      UNION ALL

      SELECT sgpa as grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ?
      `,
      [regno, regno]
    );

    // 2️⃣ If no results found → return zeros
    if (!rows.length) {
      return res.json({ sgpa: 0, percentage: 0 });
    }

    // 3️⃣ Fetch autonomous SGPA values directly (already stored in table)
    const [autonomousRows] = await pool.promise().query(
      `SELECT sgpa FROM autonomous_results WHERE regno = ? AND sgpa IS NOT NULL`,
      [regno]
    );

    const autoSGPAList = autonomousRows.map(r => parseFloat(r.sgpa));

    // 4️⃣ Sum autonomous SGPA values with maximum precision
    let totalSGPA = autoSGPAList.reduce((sum, gpa) => sum + gpa, 0);
    let count = autoSGPAList.length;

    // 5️⃣ For non-autonomous results → calculate GPA normally
    const normalResults = rows.filter(r => r.credits !== null);
    if (normalResults.length > 0) {
      const normalCalc = calculateGPA(normalResults);
      totalSGPA += parseFloat(normalCalc.gpa) * normalResults.length;
      count += normalResults.length;
    }

    // 6️⃣ Final CGPA calculation with maximum precision (NO ROUNDING)
    const cgpaRaw = count > 0 ? (totalSGPA / count) : 0;

    // 7️⃣ Percentage calculation as per JNTUK formula with maximum precision:
    //    Percentage = (CGPA − 0.75) × 10
    const percentageRaw = cgpaRaw > 0.75 ? ((cgpaRaw - 0.75) * 10) : 0;

    // 8️⃣ Return RAW decimal values - NO toFixed() here!
    // Frontend will handle exact formatting
    res.json({
      sgpa: cgpaRaw,           // Raw CGPA (e.g., 7.602)
      percentage: percentageRaw // Raw percentage (e.g., 76.02)
    });

  } catch (err) {
    console.error("❌ Failed to fetch overall results:", err);
    res.status(500).json({ sgpa: 0, percentage: 0 });
  }
});


// result verification
// ✅ Verify result (includes both results + autonomous_results)
app.get("/api/verify-result", async (req, res) => {
  const { regno, sem } = req.query;
  if (!regno || !sem) return res.status(400).json({ error: "Missing regno or sem" });

  function queryAsync(sql, values) {
    return new Promise((resolve, reject) => {
      pool.query(sql, values, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }

  try {
    // 🟢 Fetch results from BOTH tables
    const results = await queryAsync(
      `
      SELECT subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [regno, sem, regno, sem]
    );

    // 🟢 Fetch student details
    const studentRows = await queryAsync(
      "SELECT name, reg_no, course, photo_url FROM students WHERE reg_no = ?",
      [regno]
    );
    const student = studentRows[0] || {};

    // 🟢 GPA Calculation
    const gradeMap = { "A+": 10, S: 10, A: 9, B: 8, C: 7, D: 6, E: 5, F: 0, Ab: 0 };
    let totalCredits = 0, totalPoints = 0;

    results.forEach(r => {
      const gp = gradeMap[r.grade] ?? 0;

      // ✅ If autonomous results don't have credits, assume 3
      const credits = r.credits !== null ? r.credits : 3;

      totalCredits += credits;
      totalPoints += gp * credits;
    });

    const sgpa = totalCredits ? (totalPoints / totalCredits).toFixed(2) : "N/A";

    res.json({
      name: student.name || "N/A",
      regno: student.reg_no || regno,
      course: student.course || "N/A",
      semester: sem,
      photo_url: student.photo_url || null,
      sgpa,
      results
    });
  } catch (err) {
    console.error("❌ Verification error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// generate results certificate (supports results + autonomous_results)
app.get("/generate-certificate/:userId", async (req, res) => {
  const { userId } = req.params;
  const semester = req.query.semester;
  if (!semester) return res.status(400).send("Semester is required");

  const doc = new PDFDocument({ size: "A4", margin: 40 });
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=Result_${userId}_${semester}.pdf`);
  doc.pipe(res);

  function queryAsync(sql, values) {
    return new Promise((resolve, reject) => {
      pool.query(sql, values, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }

  const gradePointMap = {
    "A+" :10, S: 10, A: 9, B: 8, C: 7, D: 6, E: 5, F: 0, Ab: 0, ABSENT: 0, Completed: 0
  };

  try {
    // 🟢 Fetch results from BOTH tables
    const results = await queryAsync(
      `
      SELECT regno, subcode, subname, grade, credits 
      FROM results 
      WHERE regno = ? AND semester = ?

      UNION ALL

      SELECT regno, subcode, subname, grade, NULL as credits 
      FROM autonomous_results 
      WHERE regno = ? AND semester = ?
      `,
      [userId, semester, userId, semester]
    );

    if (!results.length) {
      doc.fontSize(14).text("❌ No results found", 100, 100);
      doc.end();
      return;
    }

    // 🟢 Fetch student info
    const studentRows = await queryAsync(
      "SELECT name, reg_no, course, father_name, photo_url FROM students WHERE userId = ?",
      [userId]
    );
    const student = studentRows[0] || {};
    const reg = student.reg_no || "";

    // 🟢 Decide JNTUK vs Autonomous header
    const isJNTUK = /^([0-1][0-9]|23)B8/.test(reg);
    const isAutonomous = /^24B8/.test(reg);

    if (isJNTUK) {
      const logoPath = path.join(__dirname, "public", "jntuk_logo.png");
      if (fs.existsSync(logoPath)) {
        doc.image(logoPath, 40, 40, { width: 60 });
      }
      doc
        .font("Helvetica-Bold")
        .fillColor("#7A0C0C")
        .fontSize(14)
        .text("JAWAHARLAL NEHRU TECHNOLOGICAL UNIVERSITY KAKINADA", 110, 45)
        .text("KAKINADA - 533003, ANDHRA PRADESH, INDIA", 110, 65);

      doc.moveTo(40, 100).lineTo(555, 100).stroke("#000");
    } else if (isAutonomous) {
      const headerPath = path.join(__dirname, "public", "logo.png"); // autonomous logo/header
      if (fs.existsSync(headerPath)) {
        doc.image(headerPath, { fit: [520, 120], align: "center" });
      }
    }

    // 🟢 Student Info
    doc.moveDown(2);
    const startY = doc.y;
    let lineY = startY;
    const labelX = 40;
    const valueX = 180;

    doc.font("Helvetica").fillColor("black").fontSize(10);
    doc.text("STUDENT NAME    :", labelX, lineY);
    doc.text(student.name || "N/A", valueX, lineY); lineY += 26;
    doc.text("FATHER'S NAME   :", labelX, lineY);
    doc.text(student.father_name || "N/A", valueX, lineY); lineY += 26;
    doc.text("REGISTRATION NO :", labelX, lineY);
    doc.text(student.reg_no || "N/A", valueX, lineY); lineY += 26;
    doc.text("COURSE          :", labelX, lineY);
    doc.text(`B.TECH - ${student.course || "N/A"}`, valueX, lineY); lineY += 26;
    doc.text("YEAR - SEMESTER :", labelX, lineY);
    doc.text(semester.toUpperCase(), valueX, lineY);

    // 🟢 Student Photo
    const photo_url = student.photo_url;
    if (photo_url) {
      try {
        const photoRes = await axios.get(photo_url, {
          responseType: "arraybuffer",
          headers: { "User-Agent": "Mozilla/5.0" }
        });
        doc.image(photoRes.data, 400, startY, { fit: [100, 120] });
      } catch {
        doc.rect(400, startY, 100, 120).stroke();
      }
    } else {
      doc.rect(400, startY, 100, 120).stroke();
    }

    // 🟢 Results Table
    doc.y = lineY + 60;
    const tableTop = doc.y;
    const rowHeight = 30;
    const colX = [40, 80, 180, 400, 460];
    const colWidths = [40, 100, 220, 60, 60];

    // watermark
    const watermarkPath = path.join(__dirname, "public", "jntuk_logo.png");
    if (isJNTUK && fs.existsSync(watermarkPath)) {
      doc.opacity(0.1).image(watermarkPath, 160, tableTop + 60, { width: 250 });
      doc.opacity(1);
    }

    doc.font("Helvetica-Bold").fontSize(9);
    ["S.No", "Sub Code", "Subject Name", "Grade", "Credits"].forEach((text, i) => {
      doc.rect(colX[i], tableTop, colWidths[i], rowHeight).stroke();
      doc.text(text, colX[i] + 2, tableTop + 8, { width: colWidths[i] - 4, align: "center" });
    });

    doc.font("Helvetica").fontSize(9);
    let totalCredits = 0, weightedSum = 0;
    results.forEach((row, i) => {
      const y = tableTop + rowHeight * (i + 1);
      const gradePoint = gradePointMap[row.grade?.toUpperCase()?.trim()] ?? 0;

      // ✅ Autonomous subjects have NULL credits → assume 3
      const credits = row.credits !== null ? parseFloat(row.credits) : 0 ;

      weightedSum += gradePoint * credits;
      totalCredits += credits;

      const data = [i + 1, row.subcode, row.subname, row.grade, credits];
      data.forEach((text, j) => {
        doc.rect(colX[j], y, colWidths[j], rowHeight).stroke();
        doc.text(String(text), colX[j] + 2, y + 8, {
          width: colWidths[j] - 4,
          align: "center"
        });
      });
    });

    const calculatedSGPA = totalCredits > 0 ? (weightedSum / totalCredits).toFixed(2) : "N/A";
    const finalTableY = tableTop + rowHeight * (results.length + 1);
    doc.font("Helvetica-Bold").fontSize(10);
    doc.text(`SEMESTER GRADE POINT AVERAGE (SGPA): ${calculatedSGPA}`, 100, finalTableY + 25, {
      width: 250,
      align: "center"
    });

    // footer legend
    doc.font("Helvetica").fontSize(8).fillColor("black");
    doc.text("CP: COMPLETED   NCP: NOT-COMPLETED   MP: Malpractice   WH: Withheld   P: Pass   F: Fail   AB: Absent", 40, finalTableY + 50);

    // QR
    const qrText = `https://crr-noc.onrender.com/verifyresult.html?regno=${userId}&sem=${semester}`;
    const qrDataURL = await QRCode.toDataURL(qrText);
    const qrBuffer = Buffer.from(qrDataURL.split(",")[1], "base64");
    doc.image(qrBuffer, 440, 670, { width: 80 });

    // signatures
    doc.font("Helvetica").fontSize(10);
    doc.text("Controller of Examinations", 40, 740);
    doc.text("Principal", 320, 740);

    const date = new Date().toLocaleDateString("en-GB").replace(/\//g, "-");
    doc.fontSize(6).text(`ISSUED DATE: ${date}`, 440, 790, { align: "right", width: 100 });

    doc.end();
  } catch (err) {
    console.error("❌ PDF generation error:", err);
    doc.fontSize(12).text("Something went wrong while generating the result.");
    doc.end();
  }
});

//admin create noc 
app.post('/admin/manual-create-noc', (req, res) => {
  const { regno, year, feeStatus } = req.body;

  if (!regno || !year || !feeStatus) {
    return res.status(400).json({ success: false, message: "Missing required fields." });
  }

  const fileName = `manual_noc_${regno}_year${year}.pdf`;
  const filePath = path.join(__dirname, 'uploads', fileName);

  const doc = new PDFDocument({ margin: 50 });
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  // Header
  const headerPath = path.join(__dirname, 'public', 'noc_header.jpg');
  if (fs.existsSync(headerPath)) {
    doc.image(headerPath, { fit: [500, 150], align: 'center' });
    doc.moveDown(3);
  }

  doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE', {
    align: 'center',
    underline: true
  });
  doc.moveDown();

  doc.font('Times-Roman').fontSize(12).text(`Reg No: ${regno}`);
  doc.text(`Academic Year: ${year}`);
  doc.moveDown();
  doc.text(`This is to certify that the student has the following fee details:`);
  doc.moveDown();

  const readableMap = {
    tuition: "TUTION FEE",
    hostel: "HOSTEL FEE",
    bus: "BUS FEE",
    university: "UNIVERSITY FEE",
    semester: "EXAMINATION CELL",
    library: "LIBRARY FEE",
    fines: "FINE"
  };

  const leftX = 70, rightX = 350, rowHeight = 20;
  let y = doc.y;

  // Prepare plain string for QR
  let qrString = `Reg No: ${regno}\nYear: ${year}\n`;

  for (const key in feeStatus) {
    const label = readableMap[key] || key.toUpperCase();
    const status = feeStatus[key]?.status || "Not Specified";
    const amount = feeStatus[key]?.amount || "-";
    doc.text(label, leftX, y);
    doc.text(`${status.toUpperCase()} ${amount !== "-" ? `(₹${amount})` : ""}`, rightX, y);
    y += rowHeight;

    qrString += `${label}: ${status} ₹${amount}\n`;
  }

  doc.moveDown();
  doc.text(`This is a system-generated certificate and does not require a manual signature.`, {
    align: 'center'
  });
  doc.moveDown();
  doc.font('Times-Bold').text("COLLEGE STAMP", { align: 'center' });

  QRCode.toDataURL(qrString, (err, qrUrl) => {
    if (err) {
      console.error("QR code generation failed", err);
      doc.end();
      return res.status(500).json({ success: false, message: "QR generation failed." });
    }

    const qrSize = 50;
    doc.image(qrUrl, 150, doc.y, { width: qrSize });
    doc.fontSize(10).text("Scan to view details", 145, doc.y + qrSize + 5, {
      width: 100,
      align: 'center'
    });

    const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
    if (fs.existsSync(footerPath)) {
      doc.image(footerPath, (doc.page.width - 500) / 2, doc.page.height - 100, { width: 500 });
    }

    doc.end();

    stream.on("finish", () => {
      // 🔁 Send the PDF file as a download
      res.download(filePath, fileName, (err) => {
        if (err) {
          console.error("Download error:", err);
          res.status(500).json({ success: false, message: "Download failed." });
        }
      });
    });
  });
});
ENC_KEY=12345678901234567890123456789012
ENC_IV=1234567890123456
//verify manual noc by qr
// Manual NOC QR Verification Page
app.get("/verify-noc/manual", (req, res) => {
  const { regno, year, ...rest } = req.query;
  if (!regno || !year) return res.send("❌ Invalid QR code.");

  let html = `
    <h2>✅ Manual NOC Verified</h2>
    <p><strong>Reg No:</strong> ${regno}</p>
    <p><strong>Academic Year:</strong> ${year}</p>
    <h3>Fee Status:</h3>
    <ul>`;

  const feeTypes = ["tuition", "hostel", "bus", "university", "semester", "library", "fines"];
  feeTypes.forEach(type => {
    const status = rest[`${type}Status`] || "-";
    const amount = rest[`${type}Amount`] || "-";
    html += `<li>${type.toUpperCase()}: ${status} - ₹${amount}</li>`;
  });

  html += `</ul><p>This NOC is verified by the system.</p>`;
  res.send(html);
});

// add counselling students
app.post("/assign-counselling", async (req, res) => {
  const {
    fromReg,
    toReg,
    counsellorName,
    counsellorMobile,
    counsellorId
  } = req.body;

  if (!fromReg || !toReg || !counsellorName || !counsellorMobile || !counsellorId) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const query = `
    UPDATE students
    SET counsellor_name = ?, counsellor_mobile = ?, counsellor_id = ?
    WHERE reg_no BETWEEN ? AND ?;
  `;

  pool.query(
    query,
    [counsellorName, counsellorMobile, counsellorId, fromReg, toReg],
    (err, result) => {
      if (err) {
        console.error("❌ Error updating students:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      return res.status(200).json({
        message: `✅ Successfully assigned counsellor to ${result.affectedRows} students.`
      });
    }
  );
});

app.get("/my-counselling-students/:staffId", (req, res) => {
  const { staffId } = req.params;

  const query = `
    SELECT 
      name,
      reg_no,
      email,
      course,
      year,
      mobile_no,
      section,
      father_name,
      father_mobile
    FROM students
    WHERE counsellor_id = ?
  `;

  pool.query(query, [staffId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching counselling students:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    res.json({ success: true, students: results });
  });
});

//update father details
app.post("/update-father-details", (req, res) => {
  const { reg_no, father_name, father_mobile } = req.body;

  if (!reg_no || !father_name || !father_mobile) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  const query = `
    UPDATE students
    SET father_name = ?, father_mobile = ?
    WHERE reg_no = ?
  `;

  pool.query(query, [father_name, father_mobile, reg_no], (err, result) => {
    if (err) {
      console.error("❌ Error updating father details:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    res.json({ success: true, message: "Father details updated successfully" });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout failed:", err);
      return res.status(500).send("Logout failed");
    }
    res.clearCookie("noc_sid");
    res.redirect('/index.html');
  });
});
app.get('/check-session', (req, res) => {
  if (
    req.session.userId &&
    (req.session.role === 'admin' || req.session.role === 'exam' || req.session.role ==='accounts')
  ) {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false });
  }
});

app.post('/staff/update-student', (req, res) => {
  const {
    userId,
    name,
    dob,
    course,
    semester,
    section,
    year,
    father_name,
    father_mobile,
    mobile_no,
    email,
    admission_type,
    counsellor_name,
    counsellor_mobile
  } = req.body;

  if (!userId) {
    return res.status(400).json({ success: false, message: "Missing userId" });
  }

  const safe_admission_type = (admission_type && admission_type !== "null") ? admission_type : null;
  const safe_section = (section && section !== "null") ? section : null;

  const query = `
    UPDATE students SET
      name = ?, dob = ?, course = ?, semester = ?, section = ?, year = ?,
      father_name = ?, father_mobile = ?, mobile_no = ?, email = ?, admission_type = ?,
      counsellor_name = ?, counsellor_mobile = ?
    WHERE userId = ?
  `;

  const values = [
    name, dob, course, semester, safe_section, year,
    father_name, father_mobile, mobile_no, email, safe_admission_type,
    counsellor_name, counsellor_mobile,
    userId
  ];

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error("❌ SQL error while updating student:", err);
      return res.status(500).json({ success: false, message: "Server error while updating student." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "No student found with the given userId." });
    }

    res.json({ success: true, message: "Student profile updated successfully." });
  });
});

// 🔹 Route: Get all students in HOD's department
app.get('/hod/students', (req, res) => {
  const { staffId } = req.query;

  console.log("📥 Incoming request to /hod/students with staffId:", staffId);

  if (!staffId || !staffId.toUpperCase().startsWith("HOD")) {
    console.warn("⚠️ Invalid or missing staffId");
    return res.status(400).json({ error: "Invalid or missing staffId" });
  }

  const deptCode = staffId.toUpperCase().replace("HOD", "");
  console.log("🧩 Extracted deptCode:", deptCode);

  // Use your existing MySQL connection (change `connection` to whatever you're using)
  pool.query(
    `SELECT name, reg_no, course, year, section, mobile_no, email, father_name, father_mobile
     FROM students WHERE dept_code = ?`,
    [deptCode],
    (err, results) => {
      if (err) {
        console.error("❌ Database error in /hod/students:", err.message);
        return res.status(500).json({ error: "Internal server error" });
      }

      console.log(`📊 Retrieved ${results.length} students for dept ${deptCode}`);

      return res.json({
        status: "success",
        total: results.length,
        students: results,
      });
    }
  );
});

app.get("/hod/pass-fail-stats", (req, res) => {
  const { staffId, year, course, section } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }

  const deptCode = staffId.replace("HOD", "");
  const filters = ["s.dept_code = ?"];
  const params = [deptCode];

  if (year) { filters.push("s.year = ?"); params.push(year); }
  if (course) { filters.push("s.course = ?"); params.push(course); }
  if (section) { filters.push("s.section = ?"); params.push(section); }

  const query = `
    SELECT s.year, s.course, s.section,
      COUNT(DISTINCT s.reg_no) AS total_students,
      SUM(CASE WHEN failed.regno IS NOT NULL THEN 1 ELSE 0 END) AS failed_students
    FROM students s
    LEFT JOIN (
      SELECT DISTINCT TRIM(UPPER(regno)) AS regno
      FROM results
      WHERE grade IN ('F','Ab','NOT_COMPLETED','MP')

      UNION

      SELECT DISTINCT TRIM(UPPER(regno)) AS regno
      FROM autonomous_results
      WHERE grade IN ('F','Ab','NOT_COMPLETED','MP','Completed','-Ab-')
    ) AS failed
    ON failed.regno = TRIM(UPPER(s.reg_no))
    WHERE ${filters.join(" AND ")}
    GROUP BY s.year, s.course, s.section
    ORDER BY s.year, s.course, s.section
  `;

  pool.query(query, params, (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching pass/fail stats:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const stats = rows.map(row => {
      const pass = row.total_students - row.failed_students;
      return {
        year: row.year,
        course: row.course,
        section: row.section,
        total_students: row.total_students,
        passed_students: pass,
        failed_students: row.failed_students,
        pass_percent: row.total_students === 0 ? 0 : Math.round((pass / row.total_students) * 100),
        fail_percent: row.total_students === 0 ? 0 : Math.round((row.failed_students / row.total_students) * 100)
      };
    });

    res.json({ stats });
  });
});


app.get("/hod/courses", (req, res) => {
  const { staffId, year } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }
  if (!year) {
    return res.status(400).json({ error: "Year is required" });
  }

  const deptCode = staffId.replace("HOD", "");

  const query = `
    SELECT DISTINCT course FROM students
    WHERE dept_code = ? AND year = ?
    ORDER BY course
  `;

  pool.query(query, [deptCode, year], (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching courses:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(rows.map(r => r.course));
  });
});


app.get("/hod/sections", (req, res) => {
  const { staffId, year, course } = req.query;

  if (!staffId || !staffId.startsWith("HOD")) {
    return res.status(400).json({ error: "Invalid HOD Staff ID" });
  }
  if (!year || !course) {
    return res.status(400).json({ error: "Year and Course required" });
  }

  const deptCode = staffId.replace("HOD", "");

  const query = `
    SELECT DISTINCT section FROM students
    WHERE dept_code = ? AND year = ? AND course = ?
    ORDER BY section
  `;

  pool.query(query, [deptCode, year, course], (err, rows) => {
    if (err) {
      console.error("🔥 Error fetching sections:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(rows.map(r => r.section));
  });
});


function cleanRow(row) {
  const cleaned = {};
  for (let key in row) {
    const cleanKey = key.replace(/\uFEFF/g, "").trim(); // Remove BOM + trim
    cleaned[cleanKey] = typeof row[key] === "string" ? row[key].trim() : row[key];
  }
  return cleaned;
}

app.post('/admin/upload-students', upload.single("studentfile"), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

  const fileExt = path.extname(req.file.originalname).toLowerCase();
  let results = [];

  const insertStudents = (rows) => {
    let insertCount = 0;
    let updateCount = 0;

    rows.forEach((rawRow) => {
      const student = cleanRow(rawRow);

      const userId = student.userId || student["﻿userId"];
      const reg_no = student.reg_no;
      const uniqueId = student.uniqueId;

      if (!userId || !reg_no || !uniqueId) {
        console.warn("❌ Skipping row due to missing critical fields:", student);
        return;
      }

      // Insert or update in users
      const userQuery = `
        INSERT INTO users (userid, password, role)
        VALUES (?, ?, 'student')
        ON DUPLICATE KEY UPDATE password = VALUES(password)
      `;

      pool.query(userQuery, [userId, userId], (userErr) => {
        if (userErr) {
          console.error("❌ User insert failed:", userErr);
          return;
        }

        const studentQuery = `
          INSERT INTO students (
            userId, name, dob, reg_no, uniqueId, year, course, dept_code, semester,
            aadhar_no, mobile_no, email, father_name, father_mobile,
            admission_type, photo_url, photo_public_id, section,
            counsellor_name, counsellor_mobile, counsellor_id
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            name = VALUES(name), dob = VALUES(dob), year = VALUES(year),
            course = VALUES(course), dept_code = VALUES(dept_code), semester = VALUES(semester),
            aadhar_no = VALUES(aadhar_no), mobile_no = VALUES(mobile_no), email = VALUES(email),
            father_name = VALUES(father_name), father_mobile = VALUES(father_mobile),
            admission_type = VALUES(admission_type), photo_url = VALUES(photo_url),
            photo_public_id = VALUES(photo_public_id), section = VALUES(section),
            counsellor_name = VALUES(counsellor_name), counsellor_mobile = VALUES(counsellor_mobile),
            counsellor_id = VALUES(counsellor_id)
        `;

        const values = [
          userId,
          student.name || null,
          student.dob || null,
          reg_no,
          uniqueId,
          student.year || null,
          student.course || null,
          student.dept_code || null,
          student.semester || null,
          student.aadhar_no || null,
          student.mobile_no || null,
          student.email || null,
          student.father_name || null,
          student.father_mobile || null,
          student.admission_type || null,
          student.photo_url || null,
          student.photo_public_id || null,
          student.section || null,
          student.counsellor_name || null,
          student.counsellor_mobile || null,
          student.counsellor_id || null
        ];

        pool.query(studentQuery, values, (studentErr, result) => {
          if (studentErr) {
            console.error("❌ Student insert/update failed:", studentErr);
          } else {
            if (result.affectedRows === 1) insertCount++;
            else if (result.affectedRows === 2) updateCount++;
          }
        });
      });
    });

    fs.unlinkSync(req.file.path);

    setTimeout(() => {
      res.json({
        success: true,
        message: `✅ Upload complete! ${insertCount} inserted, ${updateCount} updated.`,
      });
    }, 1500);
  };

  // Handle file
  if (fileExt === ".csv") {
    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on("data", (row) => results.push(cleanRow(row)))
      .on("end", () => insertStudents(results));
  } else if (fileExt === ".xlsx") {
    const workbook = xlsx.readFile(req.file.path);
    const sheetName = workbook.SheetNames[0];
    results = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);
    results = results.map(cleanRow);
    insertStudents(results);
  } else {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ success: false, message: "Unsupported file format." });
  }
});

app.post("/upload-midmarks", upload.single("file"), (req, res) => {
  const filePath = req.file.path;
  const results = [];

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => {
      results.push([
        row["CC"],
        row["HALLTICKET"],
        row["SUB CODE"],
        row["MID-1 (15M)"],
        row["A-1(5M)"],
        row["Q-1(20M)"],
        row["MID-2(15M)"],
        row["A-2(5M)"],
        row["Q-2(20M)"],
        row["LDS(30)/STATUS"],
        row["REG"],
        row["YEAR"],
        row["SEM"],
      ]);
    })
    .on("end", () => {
      const sql = `
        INSERT INTO mid_internal_marks
        (cc, hallticket, sub_code, mid1, a1, q1, mid2, a2, q2, lds_or_status, regulation, year, semester)
        VALUES ?
      `;
      pool.query(sql, [results], (err) => {
        fs.unlinkSync(filePath);
        if (err) return res.status(500).json({ error: err });
        res.json({ message: "✅ CSV Data inserted", count: results.length });
      });
    });
});

// midmarks route for students
app.get("/student/midmarks/:regno", (req, res) => {
  const { regno } = req.params;
  const { year, semester } = req.query;

  const sql = `
    SELECT sub_code, mid1, a1, q1, mid2, a2, q2, lds_or_status
    FROM mid_internal_marks
    WHERE hallticket = ? AND year = ? AND semester = ?
  `;

  pool.query(sql, [regno, year, semester], (err, results) => {
    if (err) {
      console.error("❌ Error fetching mid marks:", err.message);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (!results.length) {
      return res.status(404).json({ message: "No mid marks found" });
    }

    res.json({
      regno,
      year,
      semester,
      midmarks: results,
    });
  });
});



// get mid marks for the councelling
app.get("/student/midmarks/:regno", (req, res) => {
  const { regno } = req.params;
  const { year, semester } = req.query;

  console.log("📥 Incoming Mid Marks Request:", { regno, year, semester });

const sql = `
  SELECT sub_code, mid1, a1, q1, mid2, a2, q2, lds_or_status 
  FROM mid_internal_marks 
  WHERE hallticket = ? AND TRIM(year) = ? AND TRIM(semester) = ?
`;


  pool.query(sql, [regno, year, semester], (err, rows) => {
    if (err) {
      console.error("❌ Error fetching mid marks:", err);
      return res.status(500).json({ error: "DB error while fetching mid marks" });
    }

    if (rows.length === 0) {
      console.warn("⚠️ No mid marks found for:", { regno, year, semester });
      return res.json({ regno, year, semester, midmarks: [] });
    }

    res.json({
      regno,
      year,
      semester,
      midmarks: rows,
    });
  });
});

//hod mid marks 
app.get("/api/midmarks/search", (req, res) => {
  const { regno, year, semester } = req.query;

  if (!regno || !year || !semester) {
    return res.status(400).json({ error: "Missing required query parameters" });
  }

  console.log("Mid Marks Search:", { regno, year, semester });

  const sql = `
    SELECT 
      hallticket AS regno,
      sub_code AS subcode,
      mid1, a1, q1,
      mid2, a2, q2,
      lds_or_status
    FROM mid_internal_marks
    WHERE 
      hallticket = ?
      AND TRIM(year) = ?
      AND TRIM(semester) = ?
  `;

  pool.query(sql, [regno, year, semester], (err, results) => {
    if (err) {
      console.error("❌ DB Error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json(results);
  });
});

// 🆕 Fetch Mid Internal Marks Semester-wise
app.get("/student/internals/:regno", (req, res) => {
  const regno = req.params.regno;  // hallticket / registration number
  const semester = req.query.semester;

  if (!regno || !semester) {
    return res.status(400).json({ error: "Missing hallticket or semester" });
  }

  const query = `
    SELECT 
      sub_code AS subcode,
      mid1,
      mid2,
      a1,
      q1,
      a2,
      q2
    FROM mid_internal_marks
    WHERE hallticket = ? AND semester = ?
  `;

  pool.query(query, [regno, semester], (err, results) => {
    if (err) {
      console.error("❌ Error fetching mid marks:", err);
      return res.status(500).json({ error: "Server error fetching internals" });
    }

    if (results.length === 0) {
      return res.json({
        regno,
        semester,
        internals: [],
        message: "No internal marks found for this semester"
      });
    }

    res.json({
      regno,
      semester,
      internals: results
    });
  });
});

//  HOD send notification route
app.post('/api/notifications/send', (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }

  // Allow HOD, Principal, Correspondent
  const allowedPrefixes = ["HOD", "PRINCIPAL", "CORRESPONDENT"];
  const isAuthorized = allowedPrefixes.some(prefix => userId.toUpperCase().startsWith(prefix));

  if (!isAuthorized) {
    return res.status(403).json({ success: false, message: 'Unauthorized user' });
  }

  const sql = 'INSERT INTO notifications (staffId, message) VALUES (?, ?)';
  const values = [userId, message];

  pool.query(sql, values, (err) => {
    if (err) {
      console.error('❌ DB Error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, message: 'Notification sent successfully' });
  });
});



//get dept wise notifications
app.get('/student/notifications/:userId', (req, res) => {
  const userId = req.params.userId;

  // 1. Get the student's department
  const getDeptQuery = `SELECT dept_code FROM students WHERE userId = ?`;

  pool.query(getDeptQuery, [userId], (err, deptResult) => {
    if (err) {
      console.error('❌ Error fetching department:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (deptResult.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const deptCode = deptResult[0].dept_code;
    const deptHOD = 'HOD' + deptCode.toUpperCase(); // ensure HODCSE format

    // 2. Fetch notifications
    const getNotificationsQuery = `
      SELECT * FROM notifications
      WHERE staffId = ?
         OR UPPER(staffId) LIKE 'PRINCIPAL%'
         OR UPPER(staffId) LIKE 'CORRESPONDENT%'
        OR staffId = 'ALL' 
      ORDER BY date_sent DESC
    `; //  'ALL' IS FOR FUTURE PURPOSE

    const params = [deptHOD];

    pool.query(getNotificationsQuery, params, (err, notificationsResult) => {
      if (err) {
        console.error('❌ Error fetching notifications:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({ success: true, notifications: notificationsResult });
    });
  });
});



app.get('/api/departments', (req, res) => {
  const sql = 'SELECT DISTINCT dept_code FROM students';
  pool.query(sql, (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch departments' });
    res.json(result);
  });
});


app.get('/api/years/:dept_code', (req, res) => {
  const dept_code = req.params.dept_code;
  const sql = 'SELECT DISTINCT year FROM students WHERE dept_code = ?';
  pool.query(sql, [dept_code], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch years' });
    res.json(result);
  });
});

app.get('/api/courses-by-year', (req, res) => {
  const { dept_code, year } = req.query;
  const sql = 'SELECT DISTINCT course FROM students WHERE dept_code = ? AND year = ?';
  pool.query(sql, [dept_code, year], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch courses' });
    res.json(result);
  });
});

app.get('/api/sections', (req, res) => {
  const { dept_code, year, course } = req.query;
  const sql = `
    SELECT DISTINCT section FROM students 
    WHERE dept_code = ? AND year = ? AND course = ?
  `;
  pool.query(sql, [dept_code, year, course], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch sections' });
    res.json(result);
  });
});

// ✅ Fetch staff details (works for both /staff/:id and /api/staff/:id)
app.get(['/staff/:id', '/api/staff/:id'], (req, res) => {
  const staffId = req.params.id;
  const sql = `
    SELECT staff_id, staff_name, staff_email, mobile_no, dept_code, photo_url, photo_public_id
    FROM staff 
    WHERE staff_id = ?
  `;

  pool.query(sql, [staffId], (err, result) => {
    if (err) {
      console.error("❌ Error fetching staff:", err);
      return res.status(500).json({ error: 'Failed to fetch staff' });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: 'Staff not found' });
    }

    res.json({
      success: true,
      staff_id: result[0].staff_id,
      staff_name: result[0].staff_name,
      staff_email: result[0].staff_email,
      mobile_no: result[0].mobile_no,
      dept_code: result[0].dept_code,
      photo_url: result[0].photo_url || null,          // 👈 sidebar lo use avthundi
      photo_public_id: result[0].photo_public_id || null
    });
  });
});


// ✏️ Update staff profile
app.put(['/staff/:id', '/api/staff/:id'], upload.single("photo"), async (req, res) => {
  const staffId = req.params.id;
  const { staff_name, staff_email, mobile_no } = req.body;
  const file = req.file;

  if (!staff_name || !staff_email) {
    return res.status(400).json({ success: false, message: "Name and Email are required" });
  }

  try {
    let photo_url = null;
    let public_id = null;

    // Upload new photo if provided
    if (file) {
      const result = await cloudinary.uploader.upload(file.path, {
        public_id: `staff/${staffId}`,   // 👈 Save with staff/staffId
        overwrite: true,
        resource_type: "image"
      });
      photo_url = result.secure_url;
      public_id = result.public_id;
      fs.unlinkSync(file.path); // delete temp file
    }

    // SQL update fields
    let sql = `
      UPDATE staff SET
        staff_name = ?,
        staff_email = ?,
        mobile_no = ?`;

    const updateFields = [staff_name, staff_email, mobile_no || null];

    if (photo_url) {
      sql += `, photo_url = ?, photo_public_id = ?`;
      updateFields.push(photo_url, public_id);
    }

    sql += ` WHERE staff_id = ?`;
    updateFields.push(staffId);

    pool.query(sql, updateFields, (err, result) => {
      if (err) {
        console.error("❌ Staff SQL Error:", err);
        return res.status(500).json({ success: false, message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Staff not found" });
      }

      console.log("✅ Staff profile updated:", staffId);

      // 🔹 Fetch updated row to send back latest values (including photo_url)
      pool.query(
        "SELECT staff_id, staff_name, staff_email, mobile_no, photo_url, photo_public_id FROM staff WHERE staff_id = ?",
        [staffId],
        (err2, rows) => {
          if (err2) {
            console.error("❌ Fetch updated staff error:", err2);
            return res.json({
              success: true,
              message: "Updated, but fetch failed",
              photo_url: photo_url || null
            });
          }

          const updatedStaff = rows[0];
          res.json({
            success: true,
            message: "Staff details updated successfully",
            ...updatedStaff   // ✅ sends name, email, mobile, photo_url, photo_public_id
          });
        }
      );
    });

  } catch (err) {
    console.error("❌ Staff Update Error:", err);
    if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});


app.post("/api/allocate", (req, res) => {
  const {
    staff_id, year, course, dept_code,
    section, semester, day,
    period1, period2, period3, period4, period5, period6, period7
  } = req.body;

  if (!staff_id || !day || !semester) {
    return res.status(400).json({ success: false, error: "Missing required fields" });
  }

  // First, check for conflicts on the same day and periods for this staff
  const checkSql = `
    SELECT * FROM staff_period_allocation
    WHERE staff_id = ? AND day = ?
  `;

  pool.query(checkSql, [staff_id, day], (err, rows) => {
    if (err) {
      console.error("❌ Error checking for conflicts:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    // Check each period value for conflict
    const periods = [period1, period2, period3, period4, period5, period6, period7];
    const existingPeriods = [];

    rows.forEach(row => {
      for (let i = 1; i <= 7; i++) {
        if (row[`period${i}`]) existingPeriods.push(`period${i}`);
      }
    });

    const conflictPeriods = [];
    for (let i = 0; i < periods.length; i++) {
      if (periods[i] && existingPeriods.includes(`period${i + 1}`)) {
        conflictPeriods.push(`Period ${i + 1}`);
      }
    }

    if (conflictPeriods.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Conflict: Staff already allocated for ${conflictPeriods.join(", ")} on ${day}`
      });
    }

    // No conflicts – proceed with allocation
    const insertSql = `
      INSERT INTO staff_period_allocation (
        staff_id, year, course, dept_code, section,
        semester, day, period1, period2, period3,
        period4, period5, period6, period7
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
      staff_id, year, course, dept_code, section,
      semester, day, period1, period2, period3,
      period4, period5, period6, period7
    ];

    pool.query(insertSql, values, (err, result) => {
      if (err) {
        console.error("❌ Allocation insert error:", err);
        return res.status(500).json({ success: false, error: "Database error" });
      }

      res.json({ success: true, message: "Period allocation saved successfully!" });
    });
  });
});

// 🔹 Get Allocated Periods by Staff (Original + Adjustments)
app.get("/api/staff-allocation", (req, res) => {
  const { staff_id, date } = req.query;

  if (!staff_id) return res.status(400).json({ error: "Missing staff_id" });

  const sql = `
    (
      SELECT year, course, semester, section, dept_code, day,
        period1, period2, period3, period4, period5, period6, period7
      FROM staff_period_allocation
      WHERE TRIM(staff_id) = TRIM(?)
    )
    UNION
    (
      SELECT year, course, semester, section, NULL AS dept_code, day,
        CASE period_no WHEN 1 THEN subject END AS period1,
        CASE period_no WHEN 2 THEN subject END AS period2,
        CASE period_no WHEN 3 THEN subject END AS period3,
        CASE period_no WHEN 4 THEN subject END AS period4,
        CASE period_no WHEN 5 THEN subject END AS period5,
        CASE period_no WHEN 6 THEN subject END AS period6,
        CASE period_no WHEN 7 THEN subject END AS period7
      FROM staff_period_adjustments
      WHERE TRIM(to_staff_id) = TRIM(?) AND date = ?
    )
  `;

  pool.query(sql, [staff_id, staff_id, date], (err, result) => {
    if (err) {
      console.error("❌ Error fetching allocations:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
    res.json(result);
  });
});

// Get Students by Year, Semester, Course & Section
app.get("/api/students-by-course-section", (req, res) => {
  const { year, semester, course, section } = req.query;

  if (!year || !semester || !course || !section) {
    return res.status(400).json({ error: "Missing year, semester, course, or section" });
  }

  const sql = `
    SELECT reg_no, name, joining_date
    FROM students
    WHERE year = ? AND semester = ? AND course = ? AND section = ?
    ORDER BY reg_no
  `;

  pool.query(sql, [year, semester, course, section], (err, result) => {
    if (err) {
      console.error("❌ Error fetching students:", err);
      return res.status(500).json({ error: "Failed to fetch students" });
    }
    res.json(result);
  });
});

// 🔹 Submit Attendance
app.post('/api/submit-attendance', (req, res) => {
  const { entries } = req.body;

  if (!Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ success: false, message: "No attendance entries submitted" });
  }

  const values = entries.map(e => [
    e.reg_no,
    e.date,
    e.period,     
    e.staff_id,
    e.course,
    e.year,
    e.semester,
    e.section,
    e.subject,
    e.status
  ]);

  const sql = `
    INSERT INTO daily_attendance 
    (reg_no, date, period, staff_id, course, year, semester, section, subject, status)
    VALUES ?
    ON DUPLICATE KEY UPDATE status = VALUES(status)
  `;

  pool.query(sql, [values], (err, result) => {
    if (err) {
      console.error("❌ Attendance insert failed:", err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    res.json({ success: true, inserted: result.affectedRows });
  });
});

// ✅ Get Period Info Route
app.get("/api/get-period-info", (req, res) => {
  const { staff_id, subject } = req.query;

  if (!staff_id || !subject) {
    return res.status(400).json({ error: "Missing staff_id or subject" });
  }

  const sql = `
    SELECT year, semester, day, 
      CASE 
        WHEN period1 = ? THEN '1'
        WHEN period2 = ? THEN '2'
        WHEN period3 = ? THEN '3'
        WHEN period4 = ? THEN '4'
        WHEN period5 = ? THEN '5'
        WHEN period6 = ? THEN '6'
        WHEN period7 = ? THEN '7'
        ELSE null 
      END AS period
    FROM staff_period_allocation
    WHERE staff_id = ? AND (
      period1 = ? OR period2 = ? OR period3 = ? OR
      period4 = ? OR period5 = ? OR period6 = ? OR period7 = ?
    )
    LIMIT 1
  `;

  const params = [
    subject, subject, subject, subject, subject, subject, subject, subject,
    staff_id,
    subject, subject, subject, subject, subject, subject
  ];

  pool.query(sql, params, (err, result) => {
    if (err) {
      console.error("Error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: "No matching period found" });
    }

    res.json(result[0]);
  });
});



// 🔹 Get Students by Section
app.get("/api/students-by-course-section", (req, res) => {
  const { year, semester, course, section } = req.query;

  if (!year || !semester || !course || !section) {
    return res.status(400).json({ error: "Missing year, semester, course, or section" });
  }

  const sql = `
    SELECT reg_no, name, joining_date
    FROM students
    WHERE year = ? AND semester = ? AND course = ? AND section = ?
    ORDER BY reg_no
  `;

  pool.query(sql, [year, semester, course, section], (err, result) => {
    if (err) {
      console.error("❌ Error fetching students:", err);
      return res.status(500).json({ error: "Failed to fetch students" });
    }
    res.json(result);
  });
});

app.get('/api/staff/semesters/:staffId', (req, res) => {
  const staffId = req.params.staffId;

  const sql = `
    SELECT DISTINCT semester 
    FROM staff_period_allocation 
    WHERE staff_id = ?
    ORDER BY 
      FIELD(semester, '1-1', '1-2', '2-1', '2-2', '3-1', '3-2', '4-1', '4-2')
  `;

  pool.query(sql, [staffId], (err, results) => {
    if (err) {
      console.error("Error fetching semesters:", err);
      return res.status(500).json({ error: "Database error" });
    }
    const semesters = results.map(row => row.semester);
    res.json({ semesters });
  });
});

// 📄 Download selected-subject attendance PDF (with lateral separation & TOTAL classes filled)
app.get("/api/download-attendance-pdf", (req, res) => {
  const { year, semester, course, section, subject, from_date, to_date } = req.query;

  if (!year || !semester || !course || !section || !subject || !from_date || !to_date) {
    return res.status(400).send("Missing required query parameters.");
  }

  const subjects = subject.split(",").map(s => s.split(":")[1]);
  const placeholders = subjects.map(() => "?").join(",");

  const query = `
    SELECT 
      a.reg_no,
      a.subject,
      COUNT(*) AS total_classes,
      SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS attended,
      s.joining_date,
      s.admission_type
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? AND a.semester = ? AND a.course = ? AND a.section = ?
      AND a.subject IN (${placeholders})
      AND a.date BETWEEN ? AND ?
    GROUP BY a.reg_no, a.subject, s.joining_date, s.admission_type
    ORDER BY a.reg_no, a.subject
  `;

  pool.query(
    query,
    [year, semester, course, section, ...subjects, from_date, to_date],
    (err, results) => {
      if (err) {
        console.error("❌ DB error:", err);
        return res.status(500).send("Database error.");
      }
      if (!results.length) {
        return res.status(404).send("No attendance records found.");
      }

      const allSubjects = Array.from(new Set(results.map(r => r.subject))).sort();
      const studentMap = {};

      results.forEach(r => {
        const reg = r.reg_no;
        const attended = parseInt(r.attended || 0, 10);
        const total_classes = parseInt(r.total_classes || 0, 10);
        const joinDate = r.joining_date ? new Date(r.joining_date) : null;
        const admissionType = r.admission_type || "regular";

        if (!studentMap[reg]) {
          studentMap[reg] = {
            regno: reg,
            subjects: {},
            total_attended: 0,
            subjectTotals: {},
            joining_date: joinDate,
            admission_type: admissionType
          };
        }
        studentMap[reg].subjects[r.subject] = attended;
        studentMap[reg].total_attended += attended;
        studentMap[reg].subjectTotals[r.subject] = total_classes;
      });

      const PDFDocument = require("pdfkit");
      const fs = require("fs");
      const path = require("path");

      const doc = new PDFDocument({ margin: 40, size: "A4", layout: "landscape" });
      const fileName = `AttendanceReport-${Date.now()}.pdf`;

      res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
      res.setHeader("Content-Type", "application/pdf");
      doc.pipe(res);

      const pageWidth = doc.page.width;
      const pageHeight = doc.page.height;
      const leftMargin = doc.page.margins.left;
      const rightMargin = doc.page.margins.right;
      const usableWidth = pageWidth - leftMargin - rightMargin;
      const signatureHeight = 70;
      const cellFontSize = 8;
      let regColWidth = 80;
      const otherColsCount = allSubjects.length + 2; // subjects + TOTAL + PERCENT
      const minColWidth = 45;
      let remainingWidth = usableWidth - regColWidth;
      let colWidth = Math.floor(remainingWidth / otherColsCount);
      if (colWidth < minColWidth) {
        colWidth = minColWidth;
        const totalNeeded = regColWidth + (colWidth * otherColsCount);
        if (totalNeeded > usableWidth) {
          regColWidth = Math.max(50, regColWidth - (totalNeeded - usableWidth));
        }
      }

      function renderPageHeader(headerText = "STATEMENT OF ATTENDANCE REPORT", totalsRowSource = null) {
        const logoPath = path.join(__dirname, "public", "crrengglogo.png");
        try {
          if (fs.existsSync(logoPath)) doc.image(logoPath, leftMargin, doc.page.margins.top, { width: 50 });
        } catch (e) {}
        const titleX = leftMargin + 60;
        const titleW = usableWidth - 60;
        doc.fontSize(14).font("Helvetica-Bold")
          .text("SIR C.R.REDDY COLLEGE OF ENGINEERING (Autonomous)", titleX, doc.page.margins.top - 2, { width: titleW, align: "center" });
        doc.fontSize(10).font("Helvetica")
          .text(`B.Tech Year - ${year}   Sem - ${semester}   Branch - ${course}   Section - ${section}`, { align: "center" });
        doc.fontSize(10).text(headerText, { align: "center" });
        doc.fontSize(8).text("Vatluru, Eluru - 534007, Eluru Dist. A.P.", { align: "center" });
        doc.fontSize(8).text(`From: ${from_date}  To: ${to_date}`, { align: "center" });
        doc.moveDown(0.5);

        let y = doc.y + 6;
        doc.moveTo(leftMargin, y).lineTo(pageWidth - rightMargin, y).stroke();
        y += 6;

        const headers = ["Regd.No", ...allSubjects, "TOTAL", "PERCENT"];
        let x = leftMargin;
        doc.fontSize(cellFontSize).font("Helvetica-Bold");
        headers.forEach((h, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          doc.save();
          doc.rect(x, y, w, 20).fillAndStroke("#007acc", "black");
          doc.fillColor("white").text(h.length > 18 ? h.substring(0, 18) + "..." : h, x + 3, y + 4, { width: w - 6, align: "center" });
          doc.restore();
          x += w;
        });
        y += 20;

        x = leftMargin;
        doc.fontSize(cellFontSize).font("Helvetica-Bold").fillColor("black");
        doc.rect(x, y, regColWidth, 20).stroke();
        doc.text("Total Classes", x + 3, y + 4, { width: regColWidth - 6, align: "center" });
        x += regColWidth;

        allSubjects.forEach(sub => {
          const totalForSubject = totalsRowSource ? totalsRowSource.subjectTotals[sub] || 0 : 0;
          doc.rect(x, y, colWidth, 20).stroke();
          doc.text(String(totalForSubject), x + 3, y + 4, { width: colWidth - 6, align: "center" });
          x += colWidth;
        });

        // TOTAL column
        const totalClassesSum = totalsRowSource
          ? allSubjects.reduce((sum, sub) => sum + (totalsRowSource.subjectTotals[sub] || 0), 0)
          : 0;
        doc.rect(x, y, colWidth, 20).stroke();
        doc.text(String(totalClassesSum), x + 3, y + 4, { width: colWidth - 6, align: "center" });
        x += colWidth;

        // PERCENT column (leave empty)
        doc.rect(x, y, colWidth, 20).stroke();
        x += colWidth;

        y += 20;
        return y;
      }

      // Regular students
      const regs = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() !== "lateral");
      let y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regs[0]);
      regs.forEach(std => {
        let possibleClasses = allSubjects.reduce((sum, sub) => sum + (std.subjectTotals[sub] || 0), 0);
        const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
        const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
        const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

        const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
        if (y + 20 > bottomLimit) {
          doc.addPage();
          y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regs[0]);
        }

        let x = leftMargin;
        rowCells.forEach((cell, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          if (i === rowCells.length - 1) {
            doc.fillColor(parseFloat(cell) < 75 ? "red" : "black");
          } else {
            doc.fillColor("black");
          }
          doc.rect(x, y, w, 20).stroke();
          doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
          x += w;
        });
        y += 20;
      });

      // Lateral students
      const laterals = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() === "lateral");
      if (laterals.length > 0) {
        doc.addPage();
        y = renderPageHeader("Lateral Entry Students", laterals[0]);
        laterals.forEach(std => {
          let possibleClasses = allSubjects.reduce((sum, sub) => sum + (std.subjectTotals[sub] || 0), 0);
          const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
          const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
          const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

          const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
          if (y + 20 > bottomLimit) {
            doc.addPage();
            y = renderPageHeader("Lateral Entry Students", laterals[0]);
          }

          let x = leftMargin;
          rowCells.forEach((cell, i) => {
            const w = (i === 0) ? regColWidth : colWidth;
            if (i === rowCells.length - 1) {
              doc.fillColor(parseFloat(cell) < 75 ? "red" : "black");
            } else {
              doc.fillColor("black");
            }
            doc.rect(x, y, w, 20).stroke();
            doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
            x += w;
          });
          y += 20;
        });
      }

      let lastY = doc.y || doc.page.margins.top;
      if ((pageHeight - doc.page.margins.bottom - lastY) < 80) {
        doc.addPage();
        lastY = doc.page.margins.top;
      }
      doc.fontSize(10).fillColor("black");
      doc.text("Faculty Signature", leftMargin + 10, lastY + 40);
      doc.text("HOD Signature", pageWidth - rightMargin - 160, lastY + 40);

      doc.end();
    }
  );
});


//fetch course and section by dept_code
app.get("/api/fetch-courses-sections", (req, res) => {
  const { dept_code, year } = req.query;

  if (!dept_code || !year) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const sql = `
    SELECT DISTINCT course, section 
    FROM students 
    WHERE dept_code = ? AND year = ?
  `;

  pool.query(sql, [dept_code, year], (err, results) => {
    if (err) {
      console.error("❌ DB error:", err);
      return res.status(500).json({ error: "DB error" });
    }

    res.json(results);
  });
});

// download section wise attendance with joining_date-based percentage + Lateral list at end
// download section wise attendance with joining_date-based percentage + Lateral list at end
app.get("/api/download-all-subjects-attendance", (req, res) => {
  const { year, course, section, semester, from_date, to_date } = req.query;
  if (!year || !course || !section || !from_date || !to_date || !semester) {
    return res.status(400).json({ error: "Missing query parameters." });
  }

  const query = `
    SELECT 
      a.reg_no,
      a.subject,
      COUNT(*) AS total_classes,
      SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS attended,
      s.joining_date,
      s.admission_type
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? 
      AND a.course = ? 
      AND a.section = ? 
      AND a.semester = ?
      AND a.date BETWEEN ? AND ?
      AND (
        s.admission_type != 'lateral' 
        OR a.date >= s.joining_date
      )
    GROUP BY a.reg_no, a.subject, s.joining_date, s.admission_type
    ORDER BY a.reg_no, a.subject
  `;

  pool.query(query, [year, course, section, semester, from_date, to_date], (err, results) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!results.length) return res.status(404).json({ error: "No data found" });

    const allSubjects = Array.from(new Set(results.map(r => r.subject))).sort();

    const studentMap = {};
    results.forEach(r => {
      const reg = r.reg_no;
      const attended = parseInt(r.attended || 0, 10);
      const total_classes = parseInt(r.total_classes || 0, 10);
      const joinDate = r.joining_date ? new Date(r.joining_date) : null;
      const admissionType = r.admission_type || "regular";

      if (!studentMap[reg]) {
        studentMap[reg] = {
          regno: reg,
          subjects: {},
          total_attended: 0,
          subjectTotals: {},
          joining_date: joinDate,
          admission_type: admissionType
        };
      }
      studentMap[reg].subjects[r.subject] = attended;
      studentMap[reg].total_attended += attended;
      studentMap[reg].subjectTotals[r.subject] = total_classes;
    });

    const PDFDocument = require("pdfkit");
    const fs = require("fs");
    const path = require("path");

    const doc = new PDFDocument({ margin: 40, size: "A4", layout: "landscape" });
    const fileName = `AttendanceReport-${Date.now()}.pdf`;
    const filePath = path.join(__dirname, "uploads", fileName);
    const writeStream = fs.createWriteStream(filePath);
    doc.pipe(writeStream);

    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const leftMargin = doc.page.margins.left;
    const rightMargin = doc.page.margins.right;
    const usableWidth = pageWidth - leftMargin - rightMargin;
    const signatureHeight = 70;
    const cellFontSize = 8;
    let regColWidth = 80;
    const otherColsCount = allSubjects.length + 2; // subjects + TOTAL + PERCENT
    const minColWidth = 45;
    let remainingWidth = usableWidth - regColWidth;
    let colWidth = Math.floor(remainingWidth / otherColsCount);
    if (colWidth < minColWidth) {
      colWidth = minColWidth;
      const totalNeeded = regColWidth + (colWidth * otherColsCount);
      if (totalNeeded > usableWidth) {
        regColWidth = Math.max(50, regColWidth - (totalNeeded - usableWidth));
      }
    }

    function renderPageHeader(headerText = "STATEMENT OF ATTENDANCE REPORT", totalsSourceStudent = null) {
      const logoPath = path.join(__dirname, "public", "crrengglogo.png");
      const topY = doc.page.margins.top;
      try {
        if (fs.existsSync(logoPath)) doc.image(logoPath, leftMargin, topY, { width: 50 });
      } catch (e) {}
      const titleX = leftMargin + 60;
      const titleW = usableWidth - 60;
      doc.fontSize(14).font("Helvetica-Bold").text("SIR C.R.REDDY COLLEGE OF ENGINEERING (Autonomous)", titleX, topY - 2, { width: titleW, align: "center" });
      doc.moveDown(0.2);
      doc.fontSize(10).font("Helvetica").text(`B.Tech Year - ${year}   Sem - ${semester}   Branch - ${course}   Section - ${section}`, { align: "center" });
      doc.fontSize(10).text(headerText, { align: "center" });
      doc.fontSize(8).text("Vatluru, Eluru - 534007, Eluru Dist. A.P.", { align: "center" });
      doc.fontSize(8).text(`From: ${from_date}  To: ${to_date}`, { align: "center" });
      doc.moveDown(0.5);

      let y = doc.y + 6;
      doc.moveTo(leftMargin, y).lineTo(pageWidth - rightMargin, y).stroke();
      y += 6;

      const headers = ["Regd.No", ...allSubjects, "TOTAL", "PERCENT"];
      let x = leftMargin;
      doc.fontSize(cellFontSize).font("Helvetica-Bold");
      headers.forEach((h, i) => {
        const w = (i === 0) ? regColWidth : colWidth;
        doc.save();
        doc.rect(x, y, w, 20).fillAndStroke("#007acc", "black");
        doc.fillColor("white").text(h.length > 18 ? h.substring(0, 18) + "..." : h, x + 3, y + 4, { width: w - 6, align: "center" });
        doc.restore();
        x += w;
      });
      y += 20;

      // Total Classes Row
      x = leftMargin;
      doc.fontSize(cellFontSize).font("Helvetica-Bold").fillColor("black");
      doc.rect(x, y, regColWidth, 20).stroke();
      doc.text("Total Classes", x + 3, y + 4, { width: regColWidth - 6, align: "center" });
      x += regColWidth;

      let totalClassesSum = 0;
      allSubjects.forEach(sub => {
        const totalForSubject = totalsSourceStudent ? (totalsSourceStudent.subjectTotals[sub] || 0) : 0;
        totalClassesSum += totalForSubject;
        doc.rect(x, y, colWidth, 20).stroke();
        doc.text(String(totalForSubject), x + 3, y + 4, { width: colWidth - 6, align: "center" });
        x += colWidth;
      });

      // Fill TOTAL column
      doc.rect(x, y, colWidth, 20).stroke();
      doc.text(String(totalClassesSum), x + 3, y + 4, { width: colWidth - 6, align: "center" });
      x += colWidth;

      // PERCENT column empty
      doc.rect(x, y, colWidth, 20).stroke();
      x += colWidth;

      y += 20;
      return y;
    }

    const regulars = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() !== "lateral");
    const laterals = Object.values(studentMap).filter(std => std.admission_type.toLowerCase() === "lateral");

    // REGULAR STUDENTS PAGE
    let y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regulars[0] || null);
    regulars.forEach(std => {
      let possibleClasses = 0;
      allSubjects.forEach(sub => {
        possibleClasses += std.subjectTotals[sub] || 0;
      });
      const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
      const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
      const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

      const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
      if (y + 20 > bottomLimit) {
        doc.addPage();
        y = renderPageHeader("STATEMENT OF ATTENDANCE REPORT", regulars[0] || null);
      }

      let x = leftMargin;
      rowCells.forEach((cell, i) => {
        const w = (i === 0) ? regColWidth : colWidth;
        if (i === rowCells.length - 1) {
          const p = parseFloat(cell) || 0;
          doc.fillColor(p < 75 ? "red" : "black");
        } else {
          doc.fillColor("black");
        }
        doc.rect(x, y, w, 20).stroke();
        doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
        x += w;
      });
      y += 20;
    });

    // LATERAL STUDENTS PAGE
    if (laterals.length > 0) {
      doc.addPage();
      y = renderPageHeader("Lateral Entry Students", laterals[0] || null);

      laterals.forEach(std => {
        let possibleClasses = 0;
        allSubjects.forEach(sub => {
          possibleClasses += std.subjectTotals[sub] || 0;
        });
        const percent = possibleClasses > 0 ? ((std.total_attended / possibleClasses) * 100).toFixed(2) : "0.00";
        const attendedCells = allSubjects.map(sub => (std.subjects[sub] != null ? String(std.subjects[sub]) : "-"));
        const rowCells = [std.regno, ...attendedCells, String(std.total_attended), percent];

        const bottomLimit = pageHeight - doc.page.margins.bottom - signatureHeight;
        if (y + 20 > bottomLimit) {
          doc.addPage();
          y = renderPageHeader("Lateral Entry Students", laterals[0] || null);
        }

        let x = leftMargin;
        rowCells.forEach((cell, i) => {
          const w = (i === 0) ? regColWidth : colWidth;
          if (i === rowCells.length - 1) {
            const p = parseFloat(cell) || 0;
            doc.fillColor(p < 75 ? "red" : "black");
          } else {
            doc.fillColor("black");
          }
          doc.rect(x, y, w, 20).stroke();
          doc.text(String(cell), x + 3, y + 4, { width: w - 6, align: "center" });
          x += w;
        });
        y += 20;
      });
    }

    // SIGNATURES
    let lastY = doc.y || doc.page.margins.top;
    const minSpaceBelow = 80;
    const spaceBelow = pageHeight - doc.page.margins.bottom - lastY;
    if (spaceBelow < minSpaceBelow) {
      doc.addPage();
      lastY = doc.page.margins.top;
    }
    const signatureY = lastY + 40;
    doc.fontSize(10).fillColor("black");
    doc.text("Faculty Signature", leftMargin + 10, signatureY);
    doc.text("HOD Signature", pageWidth - rightMargin - 160, signatureY);

    doc.end();

    writeStream.on("finish", () => {
      res.download(filePath, fileName, err => {
        if (err) {
          console.error("Download error:", err);
          return res.status(500).json({ error: "File download error" });
        }
        fs.unlink(filePath, () => {});
      });
    });

    writeStream.on("error", err => {
      console.error("PDF write error:", err);
      return res.status(500).json({ error: "PDF write error" });
    });
  });
});



// 1) Get courses & sections for dept + year
app.get("/api/fetch-courses-sections", (req, res) => {
  const { dept_code, year } = req.query;
  if (!dept_code || !year) return res.status(400).json({ error: "Missing" });

  const query = `
    SELECT DISTINCT course, section
    FROM students
    WHERE dept_code = ? AND year = ?
    ORDER BY course, section
  `;
  pool.query(query, [dept_code, year], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    // return as array of { course, section }
    res.json(rows);
  });
});
// 2) Get absent students for a specific course/section/date
app.get("/api/get-absents", (req, res) => {
  const { year, course, section, date, semester } = req.query;
  if (!year || !course || !section || !date) return res.status(400).json({ error: "Missing" });

  const q = `
    SELECT a.id, a.reg_no, s.name, a.status, a.subject, a.date, a.semester
    FROM daily_attendance a
    JOIN students s ON a.reg_no = s.reg_no
    WHERE a.year = ? AND a.course = ? AND a.section = ? AND a.date = ?
      AND a.status = 'Absent'
    ORDER BY s.reg_no
  `;
  pool.query(q, [year, course, section, date], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows); // each row has attendance id (a.id) — important for updates
  });
});

// 3) Mark a student present (idempotent, atomic)
app.post("/api/mark-present", (req, res) => {
  const { attendance_id } = req.body;
  if (!attendance_id) return res.status(400).json({ error: "Missing attendance_id" });

  const q = `
    UPDATE daily_attendance 
    SET status='Present'
    WHERE id=? AND status='Absent'
  `;
  pool.query(q, [attendance_id], (err, result) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (result.affectedRows === 0)
      return res.json({ ok: true, updated: false });
    res.json({ ok: true, updated: true });
  });
});

// Route to insert/update full week staff allocation
app.post("/api/set-staff-allocation", (req, res) => {
  const { staff_id, year, course, semester, section, allocations } = req.body;

  if (!staff_id || !year || !course || !semester || !section || !allocations) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const queries = [];

  days.forEach((day) => {
    const dayAlloc = allocations[day];
    if (!dayAlloc) return; // Skip if no allocation for that day

    const { period1, period2, period3, period4, period5, period6, period7 } = dayAlloc;

    const sql = `
      INSERT INTO staff_period_allocation (
        staff_id, year, course, semester, section, day,
        period1, period2, period3, period4, period5, period6, period7
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        period1 = VALUES(period1),
        period2 = VALUES(period2),
        period3 = VALUES(period3),
        period4 = VALUES(period4),
        period5 = VALUES(period5),
        period6 = VALUES(period6),
        period7 = VALUES(period7)
    `;

    const values = [
      staff_id,
      year,
      course,
      semester,
      section,
      day,
      period1,
      period2,
      period3,
      period4,
      period5,
      period6,
      period7,
    ];

    queries.push({ sql, values });
  });

  let completed = 0;
  let hasError = false;

  queries.forEach(({ sql, values }) => {
    pool.query(sql, values, (err) => {
      if (err) {
        console.error("❌ Error inserting/updating allocation:", err);
        hasError = true;
      }

      completed++;
      if (completed === queries.length) {
        if (hasError) {
          return res.status(500).json({ error: "Some allocations failed" });
        } else {
          return res.json({ success: true, message: "All allocations saved successfully" });
        }
      }
    });
  });
});
// allocate time table and class work starting
app.post("/api/allocate/multi", (req, res) => {
  const { allocations } = req.body;

  console.log("Received Allocations:", allocations);

  if (!Array.isArray(allocations) || allocations.length === 0) {
    return res.status(400).json({ error: "Invalid or empty allocation data" });
  }

  const sql = `
    INSERT INTO staff_period_allocation (
      staff_id, year, course, dept_code, section, day,
      period1, period2, period3, period4, period5, period6, period7, semester
    ) VALUES ?
  `;

  const values = allocations.map((row) => [
    row.staff_id,
    row.year,
    row.course,
    row.dept_code,
    row.section,
    row.day,
    row.period1,
    row.period2,
    row.period3,
    row.period4,
    row.period5,
    row.period6,
    row.period7,
    row.semester,
  ]);

  // ✅ Extract joining date logic
  const first = allocations[0];
  let dateQueries = [];
  let dateValuesList = [];

  if (first.year === "2") {
    if (first.commence_regular) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ? AND (admission_type IS NULL OR admission_type != 'Lateral')
      `);
      dateValuesList.push([
        first.commence_regular,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }

    if (first.commence_lateral) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ? AND admission_type = 'Lateral'
      `);
      dateValuesList.push([
        first.commence_lateral,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }
  } else if (["1", "3", "4"].includes(first.year)) {
    if (first.commence_common) {
      dateQueries.push(`
        UPDATE students 
        SET joining_date = ? 
        WHERE dept_code = ? AND year = ? AND course = ? AND section = ?
      `);
      dateValuesList.push([
        first.commence_common,
        first.dept_code,
        first.year,
        first.course,
        first.section
      ]);
    }
  }

  // ✅ Insert staff_period_allocation rows
  pool.query(sql, [values], async (err, result) => {
    if (err) {
      console.error("❌ Error inserting multiple allocations:", err);
      return res.status(500).json({ error: "Failed to insert allocations" });
    }

    // ✅ Execute joining_date updates one by one
    try {
      for (let i = 0; i < dateQueries.length; i++) {
        const q = dateQueries[i];
        const values = dateValuesList[i];
        await new Promise((resolve, reject) => {
          pool.query(q, values, (err2, result2) => {
            if (err2) reject(err2);
            else resolve(result2);
          });
        });
      }

      console.log("✅ Allocations and joining dates updated successfully");
      return res.json({ success: true, message: "Allocations and joining dates inserted successfully" });

    } catch (err) {
      console.error("❌ Failed to update joining date:", err);
      return res.status(500).json({ error: "Joining date update failed" });
    }
  });
});

//students getting for sms
app.post('/api/get-students-for-sms', (req, res) => {
  const { dept_code, year, course, section, reg_from, reg_to } = req.body;
  let sql = `SELECT reg_no, name, father_mobile FROM students WHERE 1=1`;
  const params = [];

  if (dept_code) { sql += ` AND dept_code = ?`; params.push(dept_code); }
  if (year) { sql += ` AND year = ?`; params.push(year); }
  if (course) { sql += ` AND course = ?`; params.push(course); }
  if (section) { sql += ` AND section = ?`; params.push(section); }
  if (reg_from && reg_to) { sql += ` AND reg_no BETWEEN ? AND ?`; params.push(reg_from, reg_to); }

  pool.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error', error: err.message });
    res.json({ success: true, data: rows });
  });
});

//send sms
const SMS_USERNAME = process.env.SMS_PROVIDER_USERNAME;
const SMS_APIKEY = process.env.SMS_PROVIDER_APIKEY;

const TEMPLATE_ID_MAP = {
  attendance: "1207175447438252519",
  midmarks: "1207175447366458267",
  university_eng: "1207175447825658891",
  university_telugu: "1207175447660496054"
};

const TEMPLATE_TEXT = {
  attendance: `ప్రియమైన తల్లిదండ్రులకు, మీ కుమారుడు/కుమార్తె {#var#} (Reg.No: {#var#}) యొక్క {#var#} సెమిస్టర్ హాజరు శాతం: {#var#}%
దయచేసి మీ పిల్లల నిరంతర హాజరును ఖచ్చితంగా నిర్ధారించండి.
SIR RAMALINGA REDDY COLLEGE`,
  midmarks: `Dear Parent, Mid marks of Your Ward {#var#} bearing regno {#var#} for sem {#var#} midmarks: {#var#}
SIR RAMALINGA REDDY COLLEGE`,
  university_eng: `Dear Parent, Your Ward {#var#} bearing regno:{#var#} has Results of Semester {#var#} of Year {#var#}.
Subjects & Grades: {#var#} SGPA: {#var#}
SIR RAMALINGA REDDY COLLEGE`,
  university_telugu: `ప్రియమైన తల్లిదండ్రులకు, మీ కుమారుడు/కుమార్తె {#var#} (Reg.No: {#var#}) కు {#var#} సంవత్సరం {#var#} సెమిస్టర్ ఫలితాలు విడుదలయ్యాయి.
విషయాలు & గ్రేడ్‌లు: {#var#} SGPA: {#var#}
SIR RAMALINGA REDDY COLLEGE`
};

function formatMessage(templateKey, data) {
  let msg = TEMPLATE_TEXT[templateKey];
  const replacements = [];

  if (templateKey === "attendance") {
    replacements.push(data.name, data.reg_no, data.semester, data.percentage);
  } else if (templateKey === "midmarks") {
    replacements.push(data.name, data.reg_no, data.semester, data.total_marks);
  } else if (templateKey === "university_eng") {
   replacements.push(data.name, data.reg_no, data.semester, data.year, data.result_link, data.sgpa);
  } else if (templateKey === "university_telugu") {
    replacements.push(data.name, data.reg_no, data.year, data.semester, data.result_link, data.sgpa);
  }

  replacements.forEach(rep => {
    msg = msg.replace("{#var#}", rep ?? "");
  });

  return msg;
}

app.post("/api/send-sms", async (req, res) => {
  try {
    const { reg_nos, senderId, template } = req.body;

    if (!reg_nos?.length) {
      return res.status(400).json({ success: false, message: "No students selected" });
    }
    if (!TEMPLATE_ID_MAP[template]) {
      return res.status(400).json({ success: false, message: "Invalid template type" });
    }

    let sql;
    if (template === "attendance") {
      sql = `SELECT s.name, s.reg_no, a.semester, a.percentage, s.father_mobile
             FROM students s
             JOIN attendance a ON a.regno = s.reg_no
             WHERE s.reg_no IN (?)`;
   } else if (template === "midmarks") {
  sql = `SELECT s.name, s.reg_no, m.semester,
            (CAST(m.mid1 AS DECIMAL) + CAST(m.a1 AS DECIMAL) + CAST(m.q1 AS DECIMAL) +
             CAST(m.mid2 AS DECIMAL) + CAST(m.a2 AS DECIMAL) + CAST(m.q2 AS DECIMAL)) AS total_marks,
            s.father_mobile
         FROM students s
         JOIN railway.mid_internal_marks m ON m.hallticket = s.reg_no
         WHERE s.reg_no IN (?)`;
} else if (template === "university_eng" || template === "university_telugu") {
  sql = `SELECT 
           ANY_VALUE(s.name) AS name,
           s.reg_no,
           ANY_VALUE(s.year) AS year,
           r.semester,
           GROUP_CONCAT(CONCAT(r.subname, ' - ', r.grade) SEPARATOR ', ') AS subjects_grades,
           ANY_VALUE(r.sgpa) AS sgpa,
           ANY_VALUE(s.father_mobile) AS father_mobile
         FROM students s
         LEFT JOIN (
           SELECT regno, semester, subname, grade, sgpa FROM autonomous_results
           UNION ALL
           SELECT regno, semester, subname, grade, sgpa FROM results
         ) r ON r.regno = s.reg_no
         WHERE s.reg_no IN (?)
         GROUP BY s.reg_no, r.semester`;
}

    
    const rows = await new Promise((resolve, reject) => {
      pool.query(sql, [reg_nos], (err, results) => {
        if (err) return reject(err);
        resolve(results);
      });
    });

    if (!rows.length) {
      return res.status(404).json({ success: false, message: "No data found for selected students" });
    }

    // Send SMS for each student
    const sendResults = [];
    for (const s of rows) {
      const cleanMobile = (s.father_mobile || "").replace(/\D/g, "").slice(-10);
      if (!cleanMobile) continue;

      const dataObj =
        template === "attendance"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, percentage: s.percentage }
          : template === "midmarks"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, total_marks: s.total_marks }
          : template === "university_eng"
          ? { name: s.name, reg_no: s.reg_no, semester: s.semester, year: s.year, result_link: `https://crr-noc.onrender.com/verifyresult.html?regno=${s.reg_no}&sem=${s.semester}`, sgpa: s.sgpa }
          : { name: s.name, reg_no: s.reg_no, year: s.year, semester: s.semester, result_link: `https://crr-noc.onrender.com/verifyresult.html?regno=${s.reg_no}&sem=${s.semester}`, sgpa: s.sgpa };

      const message = encodeURIComponent(formatMessage(template, dataObj));

      const url = `https://smslogin.co/v3/api.php?username=${SMS_USERNAME}&apikey=${SMS_APIKEY}&senderid=${senderId}&mobile=${cleanMobile}&message=${message}&templateid=${TEMPLATE_ID_MAP[template]}`;

      try {
        const apiResp = await axios.get(url, { timeout: 20000 });
        sendResults.push({ reg_no: s.reg_no, mobile: cleanMobile, status: apiResp.data });
      } catch (error) {
        sendResults.push({ reg_no: s.reg_no, mobile: cleanMobile, error: error.message });
      }
    }

    res.json({ success: true, results: sendResults });
  } catch (err) {
    console.error("Error in /api/send-sms:", err);
    res.status(500).json({ success: false, message: "Internal server error", error: err.message });
  }
});

module.exports = app;

app.post("/api/adjust-period", (req, res) => {
  const {
    from_staff_id, to_staff_id, course, year,
    section, semester, day, date, period_no, subject
  } = req.body;

  // 1️⃣ Check if Staff B is free at that time
  const checkSql = `
    SELECT 
      CASE ? 
        WHEN 1 THEN period1 
        WHEN 2 THEN period2 
        WHEN 3 THEN period3 
        WHEN 4 THEN period4 
        WHEN 5 THEN period5 
        WHEN 6 THEN period6 
        WHEN 7 THEN period7 
      END AS subject
    FROM staff_period_allocation
    WHERE staff_id=? AND day=? AND course=? AND year=? AND semester=? AND section=?
    LIMIT 1
  `;

  pool.query(
    checkSql,
    [period_no, to_staff_id, day, course, year, semester, section],
    (err, result) => {
      if (err) return res.status(500).json({ error: "DB error" });

      // Staff B is busy → Reject adjustment
      if (result.length && result[0].subject) {
        return res.status(400).json({
          error: "❌ Staff already has a class in this period."
        });
      }

      // 2️⃣ Insert adjustment record
      const insertSql = `
        INSERT INTO staff_period_adjustments
        (from_staff_id, to_staff_id, course, year, section, semester, day, date, period_no, subject)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      pool.query(
        insertSql,
        [from_staff_id, to_staff_id, course, year, section, semester, day, date, period_no, subject],
        (insertErr) => {
          if (insertErr) return res.status(500).json({ error: "Insert failed" });
          res.json({ success: true, message: "✅ Adjustment successful." });
        }
      );
    }
  );
});


// 🔹 Get Staff List in Section
app.get("/api/staff-in-section", (req, res) => {
  const { course, year, semester, section } = req.query;
  const sql = `
    SELECT DISTINCT s.staff_id, s.staff_name
    FROM staff_period_allocation spa
    JOIN staff s ON s.staff_id = spa.staff_id
    WHERE spa.course=? AND spa.year=? AND spa.semester=? AND spa.section=?;
  `;
  pool.query(sql, [course, year, semester, section], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get("/api/staff-subjects", (req, res) => {
  const { staff_id, course, year, semester, section } = req.query;

  if (!staff_id || !course || !year || !semester || !section) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  const sql = `
    SELECT DISTINCT 
      period1 AS subject FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period1 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period2 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period2 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period3 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period3 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period4 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period4 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period5 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period5 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period6 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period6 IS NOT NULL
    UNION
    SELECT DISTINCT 
      period7 FROM staff_period_allocation 
      WHERE staff_id=? AND course=? AND year=? AND semester=? AND section=? AND period7 IS NOT NULL
  `;

  const params = [
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section,
    staff_id, course, year, semester, section
  ];

  pool.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// ======== Helper Functions ========
function isPrincipalOrCorrespondent(staffId) {
  return staffId && (staffId.startsWith("principal") || staffId.startsWith("correspondent"));
}

function buildStudentFilters(q) {
  const filters = [];
  const params = [];

  const dept = q.dept || q.department || null;
  const year = q.year || null;
  const course = q.course || null;
  const section = q.section || null;

  if (dept)    { filters.push('s.dept_code = ?'); params.push(dept); }
  if (year)    { filters.push('s.year = ?');     params.push(year); }
  if (course)  { filters.push('s.course = ?');   params.push(course); }
  if (section) { filters.push('s.section = ?');  params.push(section); }

  return { filters, params };
}

// ======== Departments ========
app.get(["/principal/departments", "/correspondent/departments"], (req, res) => {
  const { staffId } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) return res.status(400).json({ error: "Unauthorized" });

  pool.query(
    "SELECT DISTINCT dept_code FROM students ORDER BY dept_code",
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows.map(r => r.dept_code));
    }
  );
});

// ======== Years ========
app.get(["/principal/years", "/correspondent/years"], (req, res) => {
  const { dept } = req.query;
  if (!dept) return res.status(400).json({ error: "Dept required" });

  pool.query(
    "SELECT DISTINCT year FROM students WHERE dept_code = ? ORDER BY year",
    [dept],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows.map(r => r.year));
    }
  );
});

// ======== Courses ========
app.get(["/principal/courses", "/correspondent/courses"], (req, res) => {
  const { dept, year } = req.query;
  if (!dept || !year) return res.status(400).json({ error: "Dept & Year required" });

  pool.query(
    "SELECT DISTINCT course FROM students WHERE dept_code = ? AND year = ? ORDER BY course",
    [dept, year],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows.map(r => r.course));
    }
  );
});

// ======== Sections ========
app.get(["/principal/sections", "/correspondent/sections"], (req, res) => {
  const { dept, year, course } = req.query;
  if (!dept || !year || !course) return res.status(400).json({ error: "Dept, Year & Course required" });

  pool.query(
    "SELECT DISTINCT section FROM students WHERE dept_code = ? AND year = ? AND course = ? ORDER BY section",
    [dept, year, course],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(rows.map(r => r.section));
    }
  );
});

// ======== Students ========
app.get(["/principal/students", "/correspondent/students"], (req, res) => {
  const { staffId } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) return res.status(400).json({ success: false, error: "Unauthorized" });

  pool.query(
    `SELECT reg_no, name, course, year, section, mobile_no, email, father_name, father_mobile, dept_code
     FROM students
     ORDER BY dept_code, year, section, reg_no`,
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, error: "Database error" });
      res.json({ success: true, students: rows });
    }
  );
});

// ======== Pass/Fail Stats ========
app.get(["/principal/pass-fail-stats", "/correspondent/pass-fail-stats"], (req, res) => {
  const { staffId, dept, year, course, section } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  if (!dept) return res.status(400).json({ error: "Dept required" });

  const filters = ["s.dept_code = ?"];
  const params = [dept];
  if (year) filters.push("s.year = ?"), params.push(year);
  if (course) filters.push("s.course = ?"), params.push(course);
  if (section) filters.push("s.section = ?"), params.push(section);

  const query = `
    SELECT s.year, s.course, s.section,
      COUNT(DISTINCT s.reg_no) AS total_students,
      SUM(CASE WHEN failed.regno IS NOT NULL THEN 1 ELSE 0 END) AS failed_students
    FROM students s
    LEFT JOIN (
      SELECT DISTINCT TRIM(UPPER(regno)) AS regno
      FROM results
      WHERE grade IN ('F','Ab','NOT_COMPLETED','MP')
      UNION
      SELECT DISTINCT TRIM(UPPER(regno)) AS regno
      FROM autonomous_results
      WHERE grade IN ('F','Ab','NOT_COMPLETED','MP','Completed','-Ab-')
    ) AS failed
    ON failed.regno = TRIM(UPPER(s.reg_no))
    WHERE ${filters.join(" AND ")}
    GROUP BY s.year, s.course, s.section
    ORDER BY s.year, s.course, s.section
  `;

  pool.query(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Internal Server Error" });

    const stats = rows.map(row => {
      const pass = row.total_students - row.failed_students;
      return {
        year: row.year,
        course: row.course,
        section: row.section,
        total_students: row.total_students,
        passed_students: pass,
        failed_students: row.failed_students,
        pass_percent: row.total_students === 0 ? 0 : Math.round((pass / row.total_students) * 100),
        fail_percent: row.total_students === 0 ? 0 : Math.round((row.failed_students / row.total_students) * 100)
      };
    });

    res.json({ stats });
  });
});

// ======== Backlog Summary ========
app.get(["/principal/backlog-summary", "/correspondent/backlog-summary"], (req, res) => {
  const { staffId } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  const query = `
    SELECT s.reg_no,
      COALESCE(SUM(
        CASE WHEN sub_backlogs.grade IN ('F','Ab','-Ab-','NOT_COMPLETED','MP') THEN 1 ELSE 0 END
      ), 0) AS backlogs
    FROM students s
    LEFT JOIN (
      SELECT regno, grade FROM results
      UNION ALL
      SELECT regno, grade FROM autonomous_results
    ) AS sub_backlogs ON sub_backlogs.regno = s.reg_no
    ${whereClause}
    GROUP BY s.reg_no
  `;

  pool.query(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Internal Server Error" });

    let zero = 0, low = 0, high = 0;
    rows.forEach(r => {
      const b = Number(r.backlogs) || 0;
      if (b === 0) zero++;
      else if (b <= 2) low++;
      else high++;
    });

    res.json({ zero, low, high });
  });
});

// ======== Backlog Details ========
app.get(["/principal/backlog-details", "/correspondent/backlog-details"], (req, res) => {
  const { staffId, type } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  const query = `
    SELECT s.reg_no,
           COALESCE(sub_backlogs.subcode, '') AS subcode,
           COALESCE(sub_backlogs.subname, '') AS subname,
           COALESCE(sub_backlogs.grade, '') AS grade
    FROM students s
    LEFT JOIN (
      SELECT regno, subcode, subname, grade FROM results
      UNION ALL
      SELECT regno, subcode, subname, grade FROM autonomous_results
    ) AS sub_backlogs ON sub_backlogs.regno = s.reg_no
    ${whereClause}
    ORDER BY s.reg_no
  `;

  pool.query(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Internal Server Error" });

    const studentsMap = new Map();
    rows.forEach(r => {
      if (!studentsMap.has(r.reg_no)) studentsMap.set(r.reg_no, []);
      if (['F','Ab','-Ab-','NOT_COMPLETED','MP'].includes(r.grade)) {
        studentsMap.get(r.reg_no).push({
          subcode: r.subcode,
          subname: r.subname,
          grade: r.grade
        });
      }
    });

    const result = [];
    for (const [reg, subs] of studentsMap.entries()) {
      const count = subs.length;
      if (type === 'zero' && count !== 0) continue;
      if (type === 'low' && !(count >= 1 && count <= 2)) continue;
      if (type === 'high' && !(count >= 3)) continue;
      result.push({ reg_no: reg, subjects: subs });
    }

    res.json({ students: result });
  });
});

app.get(["/principal/subjects", "/correspondent/subjects"], (req, res) => {
  const { staffId } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) 
    return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);

  let whereClause = '';
  if (filters.length) {
    whereClause = 'WHERE ' + filters.join(' AND ');
  }

  const query = `
    SELECT DISTINCT sb.subcode, sb.subname
    FROM (
      SELECT regno, subcode, subname FROM results
      UNION ALL
      SELECT regno, subcode, subname FROM autonomous_results
    ) AS sb
    INNER JOIN students s ON s.reg_no = sb.regno
    ${whereClause}
    AND sb.subname IS NOT NULL
    ORDER BY sb.subname
  `;

  pool.query(query, params, (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    // Return array of objects with both subcode and subname
    res.json(rows.map(r => ({ subcode: r.subcode, subname: r.subname })));
  });
});

app.get(["/principal/subject-backlogs", "/correspondent/subject-backlogs"], (req, res) => {
  const { staffId } = req.query;
  const subject = req.query.subject || req.query.subname;
  if (!isPrincipalOrCorrespondent(staffId)) 
    return res.status(400).json({ error: "Invalid Staff ID" });
  if (!subject) 
    return res.status(400).json({ error: "Subject is required" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? 'AND ' + filters.join(' AND ') : '';

  const query = `
    SELECT s.reg_no AS regno, s.name, sb.subcode, sb.subname, sb.grade
    FROM (
      SELECT regno, subcode, subname, grade FROM results
      UNION ALL
      SELECT regno, subcode, subname, grade FROM autonomous_results
    ) AS sb
    INNER JOIN students s ON s.reg_no = sb.regno
    WHERE sb.subname = ?
      AND sb.grade IN ('F','Ab','-Ab-','NOT_COMPLETED','MP')
      ${whereClause}
    ORDER BY s.reg_no
  `;

  pool.query(query, [subject, ...params], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const out = rows.map(r => ({
      regno: r.regno,
      name: r.name || '-',   // fallback if name is null
      subcode: r.subcode,
      subname: r.subname,
      grade: r.grade
    }));

    res.json(out);
  });
});

// Helper: validate staff
function validateStaff(req, res) {
  const { staffId } = req.query;
  if (!isPrincipalOrCorrespondent(staffId)) {
    res.status(400).json({ error: "Invalid Staff ID" });
    return false;
  }
  return true;
}


// ---------------- Backlog PDF by Subject (Professional Govt/Univ Style) ----------------
app.get(["/principal/backlog-pdf", "/correspondent/backlog-pdf"], (req, res) => {
  if (!validateStaff(req, res)) return;
  const { subcode } = req.query;
  if (!subcode) return res.status(400).json({ error: "subcode is required" });

  const query = `
    SELECT s.course, s.section, s.reg_no, s.name, r.grade
    FROM (
      SELECT regno, subcode, grade FROM results 
        WHERE subcode = ? AND grade NOT IN ('S','A+','A','B','C','D','E')
      UNION ALL
      SELECT regno, subcode, grade FROM autonomous_results 
        WHERE subcode = ? AND grade NOT IN ('S','A+','A','B','C','D','E')
    ) r
    INNER JOIN students s ON s.reg_no = r.regno
    ORDER BY s.course, s.section, s.reg_no
  `;

  pool.query(query, [subcode, subcode], (err, rows) => {
    if (err) return res.status(500).send("Internal Server Error");
    if (!rows || rows.length === 0) return res.status(404).send("✅ No backlogs found for this subject!");

    // sanitize
    rows.forEach(r => {
      r.name = (r.name || "").replace(/\s+/g, " ").trim();
      r.course = (r.course || "").trim();
      r.section = (r.section || "").trim();
    });

    // group by section
    const sections = {};
    rows.forEach(r => {
      const key = `${r.course}-${r.section}`.replace(/\s+/g, " ").trim();
      if (!sections[key]) sections[key] = [];
      sections[key].push(r);
    });

    const doc = new PDFDocument({ 
      margin: 50, 
      size: "A4", 
      bufferPages: true,
      autoFirstPage: true
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=backlog_report_${subcode}.pdf`);
    doc.pipe(res);

    const pageHeight = doc.page.height;
    const pageWidth = doc.page.width;
    const footerSpace = 50;
    const headerHeight = 150; // Fixed header height

    const tableX = 50;
    const colWidths = { sno: 50, reg: 120, name: 280, grade: 70 };
    const tableWidth = colWidths.sno + colWidths.reg + colWidths.name + colWidths.grade;

    let currentPageHasContent = false;

    // Professional Header
    function drawHeader() {
      currentPageHasContent = true;

      doc.font("Helvetica-Bold")
        .fontSize(18)
        .fillColor("#1a365d")
        .text("SIR C.R. REDDY COLLEGE OF ENGINEERING", tableX, 50, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      doc.font("Helvetica")
        .fontSize(11)
        .fillColor("#2d3748")
        .text("(An Autonomous Institution)", tableX, 75, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      // Decorative line
      doc.strokeColor("#1a365d")
        .lineWidth(2)
        .moveTo(tableX, 95)
        .lineTo(tableX + tableWidth, 95)
        .stroke();

      doc.font("Helvetica-Bold")
        .fontSize(15)
        .fillColor("#1a365d")
        .text("BACKLOG REPORT", tableX, 110, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      // Subject info box
      doc.rect(tableX, 135, tableWidth, 25)
        .fillColor("#f7fafc")
        .strokeColor("#cbd5e0")
        .lineWidth(1)
        .fillAndStroke();

      doc.font("Helvetica-Bold")
        .fontSize(11)
        .fillColor("#2d3748")
        .text(`Subject Code: ${subcode}`, tableX, 143, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      doc.y = 170; // Set fixed Y position after header
    }

    function needsNewPage(requiredSpace) {
      return doc.y + requiredSpace > pageHeight - footerSpace;
    }

    function addNewPage() {
      doc.addPage();
      currentPageHasContent = false;
      doc.y = 50; // Start from top of new page
    }

    function drawSectionHeader(text, total) {
      const sectionHeight = 35;

      // Check if section header fits
      if (needsNewPage(sectionHeight + 30)) {
        addNewPage();
      }

      currentPageHasContent = true;

      // Section header box
      const boxY = doc.y;
      doc.rect(tableX, boxY, tableWidth, sectionHeight)
        .fillColor("#edf2f7")
        .strokeColor("#a0aec0")
        .lineWidth(1)
        .fillAndStroke();

      const sectionText = `${text} (Total Backlogs: ${total})`;

      doc.font("Helvetica-Bold")
        .fontSize(12)
        .fillColor("#1a365d")
        .text(sectionText, tableX, boxY + 10, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      doc.y = boxY + sectionHeight + 5;
    }

    function drawTableHeader() {
      const headerHeight = 25;

      // Check if table header fits
      if (needsNewPage(headerHeight + 20)) {
        addNewPage();
        return false; // Signal that we need to redraw section header
      }

      currentPageHasContent = true;
      const y = doc.y;

      // Header background
      doc.rect(tableX, y, tableWidth, headerHeight)
        .fillColor("#2d3748")
        .fill();

      // Header borders  
      doc.rect(tableX, y, tableWidth, headerHeight)
        .strokeColor("#1a202c")
        .lineWidth(1)
        .stroke();

      // Column separators
      let x = tableX;
      [colWidths.sno, colWidths.reg, colWidths.name].forEach(width => {
        x += width;
        doc.strokeColor("#4a5568")
          .lineWidth(0.5)
          .moveTo(x, y)
          .lineTo(x, y + headerHeight)
          .stroke();
      });

      // Header text
      doc.font("Helvetica-Bold")
        .fontSize(10)
        .fillColor("white");

      doc.text("S.No", tableX, y + 8, { 
        width: colWidths.sno, 
        align: "center",
        lineBreak: false
      });

      doc.text("Registration No", tableX + colWidths.sno, y + 8, { 
        width: colWidths.reg, 
        align: "center",
        lineBreak: false
      });

      doc.text("Student Name", tableX + colWidths.sno + colWidths.reg, y + 8, { 
        width: colWidths.name, 
        align: "center",
        lineBreak: false
      });

      doc.text("Grade", tableX + colWidths.sno + colWidths.reg + colWidths.name, y + 8, { 
        width: colWidths.grade, 
        align: "center",
        lineBreak: false
      });

      doc.y = y + headerHeight;
      return true;
    }

    function drawTableRow(stu, index, isEven) {
      const rowH = 20;

      // Check if row fits
      if (needsNewPage(rowH)) {
        return false; // Signal that we need new page
      }

      currentPageHasContent = true;
      const y = doc.y;

      // Alternating row colors
      if (isEven) {
        doc.rect(tableX, y, tableWidth, rowH)
          .fillColor("#f8f9fa")
          .fill();
      }

      // Row border
      doc.rect(tableX, y, tableWidth, rowH)
        .strokeColor("#e2e8f0")
        .lineWidth(0.5)
        .stroke();

      // Column separators
      let x = tableX;
      [colWidths.sno, colWidths.reg, colWidths.name].forEach(width => {
        x += width;
        doc.strokeColor("#e2e8f0")
          .lineWidth(0.3)
          .moveTo(x, y)
          .lineTo(x, y + rowH)
          .stroke();
      });

      // Grade color coding
      let gradeColor = "#2d3748";
      if (stu.grade === "F" || stu.grade === "Ab") gradeColor = "#e53e3e";
      else if (stu.grade === "RA") gradeColor = "#d69e2e";

      // Row data
      doc.font("Helvetica")
        .fontSize(9)
        .fillColor("#2d3748");

      doc.text((index + 1).toString(), tableX, y + 5, { 
        width: colWidths.sno, 
        align: "center",
        lineBreak: false
      });

      doc.text(stu.reg_no || "N/A", tableX + colWidths.sno, y + 5, { 
        width: colWidths.reg, 
        align: "center",
        lineBreak: false
      });

      doc.text(stu.name || "N/A", tableX + colWidths.sno + colWidths.reg + 5, y + 5, { 
        width: colWidths.name - 10, 
        align: "left",
        lineBreak: false
      });

      doc.font("Helvetica-Bold")
        .fontSize(10)
        .fillColor(gradeColor)
        .text(stu.grade || "N/A", tableX + colWidths.sno + colWidths.reg + colWidths.name, y + 5, { 
          width: colWidths.grade, 
          align: "center",
          lineBreak: false
        });

      doc.y = y + rowH;
      return true;
    }

    function drawGrandTotal(grandTotal) {
      const totalHeight = 40;

      // Check if grand total fits
      if (needsNewPage(totalHeight + 20)) {
        addNewPage();
      }

      currentPageHasContent = true;

      doc.y += 15; // Add some spacing

      const totalBoxY = doc.y;

      doc.rect(tableX, totalBoxY, tableWidth, totalHeight)
        .fillColor("#f0fff4")
        .strokeColor("#38a169")
        .lineWidth(2)
        .fillAndStroke();

      doc.font("Helvetica-Bold")
        .fontSize(14)
        .fillColor("#1a365d")
        .text(`GRAND TOTAL BACKLOGS: ${grandTotal}`, tableX, totalBoxY + 12, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });

      doc.y = totalBoxY + totalHeight;
    }

    // Start drawing
    drawHeader();

    let grandTotal = 0;
    const sectionKeys = Object.keys(sections);

    for (let secIndex = 0; secIndex < sectionKeys.length; secIndex++) {
      const secKey = sectionKeys[secIndex];
      const students = sections[secKey];
      grandTotal += students.length;

      // Draw section header
      drawSectionHeader(secKey, students.length);

      // Draw table header, retry if page break occurred
      let headerDrawn = drawTableHeader();
      if (!headerDrawn) {
        drawSectionHeader(secKey, students.length);
        drawTableHeader();
      }

      // Draw students
      for (let i = 0; i < students.length; i++) {
        const stu = students[i];
        let rowDrawn = drawTableRow(stu, i, i % 2 === 0);

        if (!rowDrawn) {
          // Need new page, redraw section header and table header
          addNewPage();
          drawSectionHeader(secKey + " (continued)", students.length);
          drawTableHeader();
          drawTableRow(stu, i, i % 2 === 0);
        }
      }
    }

    // Draw grand total
    drawGrandTotal(grandTotal);

    // Add footers to all pages (only pages with content)
    const pages = doc.bufferedPageRange();
    const generatedOn = new Date().toLocaleString("en-IN", { 
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit", 
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });

    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      const y = pageHeight - 30;

      // Footer line
      doc.strokeColor("#cbd5e0")
        .lineWidth(0.5)
        .moveTo(50, y - 5)
        .lineTo(pageWidth - 50, y - 5)
        .stroke();

      doc.font("Helvetica")
        .fontSize(8)
        .fillColor("#718096")
        .text(`Generated on: ${generatedOn} | System: Academic Management`, 50, y, { align: "left" });

      doc.text(`Page ${i + 1} of ${pages.count}`, 50, y, { align: "right" });
    }

    // Finalize document
    doc.end();
  });
});

// ---------------- Fetch All Subjects Alphabetically ----------------
app.get(["/principal/all-subjects", "/correspondent/all-subjects"], (req, res) => {
  if (!validateStaff(req, res)) return;

  const query = `
    SELECT DISTINCT subcode, subname
    FROM (
      SELECT subcode, subname FROM results
      UNION
      SELECT subcode, subname FROM autonomous_results
    ) AS all_subjects
    ORDER BY subname ASC
  `;

  pool.query(query, (err, rows) => {
    if (err) {
      console.error("all-subjects error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ subjects: rows });
  });
});

// accounts copy download
// ==========================
// 1️⃣ Fetch account copy data
// ==========================
app.get("/api/accountcopy/:id", (req, res) => {
  const { id } = req.params;

  // 1️⃣ Fetch student by reg_no or uniqueId
  pool.query(
    "SELECT reg_no, name AS full_name, uniqueId FROM students WHERE reg_no = ? OR uniqueId = ?",
    [id, id],
    (err, studentRows) => {
      if (err) {
        console.error("DB Error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
      }

      if (studentRows.length === 0) {
        return res.status(404).json({ success: false, message: "Student not found" });
      }

      const student = {
        regno: studentRows[0].reg_no,
        full_name: studentRows[0].full_name,
        unique_id: studentRows[0].uniqueId
      };

      // 2️⃣ Fetch payments
      pool.query(
        "SELECT feetype, amount, transaction_date, sbi_ref_no AS reference_no FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC",
        [student.unique_id],
        (err, payments) => {
          if (err) {
            console.error("DB Error:", err);
            return res.status(500).json({ success: false, message: "Internal Server Error" });
          }

          let total_paid = 0;

          // Format payments and sum total_paid
          const formattedPayments = (payments || []).map(p => {
            const amt = parseFloat(p.amount || 0);
            total_paid += amt;
            return {
              feetype: p.feetype || "-",
              amount: amt,
              reference_no: p.reference_no || "-",
              transaction_date: p.transaction_date
                ? new Date(p.transaction_date).toISOString().split("T")[0]
                : "-"
            };
          });

// 3️⃣ Fetch fee structure for ALL semesters
pool.query(
  "SELECT tuition, hostel, bus, university, semester, `library`, fines FROM student_fee_structure WHERE reg_no = ?",
  [student.regno],
  (err, feeRows) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ success: false, message: "Internal Server Error" });
    }

    // Sum all rows to get total expected
    let total_expected = 0;
    feeRows.forEach(row => {
      total_expected +=
        (parseFloat(row.tuition) || 0) +
        (parseFloat(row.hostel) || 0) +
        (parseFloat(row.bus) || 0) +
        (parseFloat(row.university) || 0) +
        (parseFloat(row.semester) || 0) +
        (parseFloat(row.library) || 0) +
        (parseFloat(row.fines) || 0);
    });

    const total_due = total_expected - total_paid;

    res.json({
      success: true,
      student,
      payments: formattedPayments,
      totals: {
        total_expected: total_expected || 0,
        total_paid: total_paid || 0,
        total_due: total_due || 0
      }
    });
  }
);
}
);
}
);
});
 

// accounts copy download route with proper header and footer alignment
app.get("/api/accountcopy/download/:id", async (req, res) => {
  const { id } = req.params;

  pool.query(
    "SELECT reg_no, name AS full_name, uniqueId, photo_url FROM students WHERE reg_no = ? OR uniqueId = ?",
    [id, id],
    async (err, studentRows) => {
      if (err) return res.status(500).send("Internal Server Error");
      if (studentRows.length === 0) return res.status(404).send("Student not found");

      const student = studentRows[0];

      pool.query(
        "SELECT feetype, amount, transaction_date, sbi_ref_no AS reference_no FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY uploaded_on ASC",
        [student.uniqueId],
        async (err, payments) => {
          if (err) return res.status(500).send("Internal Server Error");

          let total_paid = 0;
          const formattedPayments = (payments || []).map(p => {
            const amt = parseFloat(p.amount || 0);
            total_paid += amt;
            return {
              feetype: p.feetype || "-",
              amount: amt,
              reference_no: p.reference_no || "-",
              transaction_date: p.transaction_date ? new Date(p.transaction_date).toISOString().split("T")[0] : "-"
            };
          });

          pool.query(
            "SELECT tuition, hostel, bus, university, semester, `library`, fines FROM student_fee_structure WHERE reg_no = ?",
            [student.reg_no],
            async (err, feeRows) => {
              if (err) return res.status(500).send("Internal Server Error");

              let total_expected = 0;
              feeRows.forEach(row => {
                total_expected +=
                  (parseFloat(row.tuition) || 0) +
                  (parseFloat(row.hostel) || 0) +
                  (parseFloat(row.bus) || 0) +
                  (parseFloat(row.university) || 0) +
                  (parseFloat(row.semester) || 0) +
                  (parseFloat(row.library) || 0) +
                  (parseFloat(row.fines) || 0);
              });

              const total_due = total_expected - total_paid;

              // --- PDF Generation ---
              const doc = new PDFDocument({ 
                margin: 50, 
                size: "A4",
                bufferPages: true
              });

              res.setHeader('Content-Type', 'application/pdf');
              res.setHeader('Content-Disposition', `attachment; filename=AccountCopy_${student.reg_no}.pdf`);
              doc.pipe(res);

              // --- HEADER SECTION WITH PROPER SPACING ---
              let yPosition = 50;

              // College Logo (Left) - Fixed position
              try {
                const logoPath = path.join(__dirname, 'public', 'crrengglogo.png');
                if (fs.existsSync(logoPath)) {
                  doc.image(logoPath, 50, yPosition, { width: 60, height: 60 });
                }
              } catch (err) {
                console.error("Logo error:", err);
              }

              // College Name and Details (Center) - NO OVERLAP, proper spacing
              doc.fontSize(16)
                 .fillColor('#000080')
                 .text("SIR C R REDDY COLLEGE OF ENGINEERING", 120, yPosition + 8, {
                   align: 'center',
                   width: 360
                 });

              doc.fontSize(12)
                 .fillColor('black')
                 .text("VATLURU, ELURU- 534007", 120, yPosition + 28, {
                   align: 'center',
                   width: 360
                 });

              doc.fontSize(10)
                 .fillColor('gray')
                 .text("Accredited by NBA & NAAC with (A) | Approved by AICTE | Affiliated to JNTUK", 120, yPosition + 45, {
                   align: 'center',
                   width: 360
                 });

              // Move yPosition after header content is done
              yPosition += 80;

              // Horizontal Line
              doc.strokeColor('black')
                 .lineWidth(1)
                 .moveTo(50, yPosition)
                 .lineTo(545, yPosition)
                 .stroke();

              yPosition += 20;

              // Document Title
              doc.fontSize(14)
                 .fillColor('black')
                 .text("STUDENT FEE ACCOUNT STATEMENT", {
                   align: 'center',
                   underline: true
                 });

              yPosition = doc.y + 20;

              // Generated Date (Right aligned)
              const now = new Date();
              const currentDate = now.toLocaleDateString('en-IN');
              const currentTime = now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });

              doc.fontSize(9)
                 .fillColor('gray')
                 .text(`Generated: ${currentDate} ${currentTime}`, 400, yPosition, {
                   width: 145,
                   align: 'right'
                 });

              yPosition += 30;

              // --- STUDENT DETAILS SECTION ---
              // Student Photo (Right side)
              const photoX = 450;
              const photoY = yPosition;

              if (student.photo_url) {
                try {
                  const response = await axios.get(student.photo_url, { responseType: "arraybuffer" });
                  const photoBuffer = Buffer.from(response.data, "binary");

                  // Photo border
                  doc.rect(photoX - 1, photoY - 1, 82, 107)
                     .strokeColor('gray')
                     .stroke();

                  doc.image(photoBuffer, photoX, photoY, { width: 80, height: 105 });
                } catch (err) {
                  console.error("Photo error:", err);
                  // Photo placeholder
                  doc.rect(photoX, photoY, 80, 105)
                     .strokeColor('gray')
                     .fillColor('#f5f5f5')
                     .fillAndStroke();

                  doc.fontSize(8)
                     .fillColor('gray')
                     .text("Photo Not\nAvailable", photoX + 20, photoY + 45);
                }
              } else {
                // Photo placeholder when no URL
                doc.rect(photoX, photoY, 80, 105)
                   .strokeColor('gray')
                   .fillColor('#f5f5f5')
                   .fillAndStroke();

                doc.fontSize(8)
                   .fillColor('gray')
                   .text("Photo Not\nAvailable", photoX + 20, photoY + 45);
              }

              // Student Details Box (Left side)
              doc.rect(50, yPosition, 380, 110)
                 .strokeColor('black')
                 .stroke();

              // Student Details Content
              doc.fontSize(12)
                 .fillColor('black')
                 .text("STUDENT DETAILS", 60, yPosition + 12, { underline: true });

              doc.fontSize(10)
                 .fillColor('black');

              doc.text(`Name: ${student.full_name}`, 60, yPosition + 35);
              doc.text(`Registration Number: ${student.reg_no}`, 60, yPosition + 55);
              doc.text(`Unique ID: ${student.uniqueId}`, 60, yPosition + 75);
              doc.text(`Academic Year: ${now.getFullYear()}-${now.getFullYear() + 1}`, 60, yPosition + 95);

              yPosition += 130;

              // --- FEE SUMMARY SECTION ---
              doc.fontSize(12)
                 .fillColor('black')
                 .text("FEE SUMMARY", 50, yPosition, { underline: true });

              yPosition += 25;

              // Fee Summary Table
              const summaryData = [
                ["Total Fee To be Paid", `Rs. ${total_expected.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`],
                ["Total Amount Paid", `Rs. ${total_paid.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`],
                ["Outstanding Balance", `Rs. ${total_due.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`]
              ];

              summaryData.forEach((row, index) => {
                const rowY = yPosition + (index * 25);

                // Alternating background
                if (index % 2 === 0) {
                  doc.rect(50, rowY, 495, 25)
                     .fillColor('#f8f9fa')
                     .fill();
                }

                // Row border
                doc.rect(50, rowY, 495, 25)
                   .strokeColor('black')
                   .stroke();

                // Row content
                const textColor = (index === 2 && total_due > 0) ? 'red' : 'black';

                doc.fontSize(10)
                   .fillColor(textColor)
                   .text(row[0], 60, rowY + 8, { width: 350 })
                   .text(row[1], 420, rowY + 8, { width: 115, align: 'right' });
              });

              yPosition += 100;

              // --- PAYMENT HISTORY SECTION ---
              doc.fontSize(12)
                 .fillColor('black')
                 .text("PAYMENT HISTORY", 50, yPosition, { underline: true });

              yPosition += 25;

              if (formattedPayments.length === 0) {
                doc.fontSize(10)
                   .fillColor('gray')
                   .text("No payment records found.", 50, yPosition);
                yPosition += 30;
              } else {
                // Payment Table Headers
                const headers = ["Date", "Reference No.", "Fee Type", "Amount (Rs.)"];
                const colWidths = [80, 100, 200, 115];
                const colX = [50, 130, 230, 430];

                // Header Background
                doc.rect(50, yPosition, 495, 25)
                   .fillColor('#e9ecef')
                   .fill();

                doc.rect(50, yPosition, 495, 25)
                   .strokeColor('black')
                   .stroke();

                // Header Text
                doc.fontSize(10)
                   .fillColor('black');

                headers.forEach((header, i) => {
                  doc.text(header, colX[i], yPosition + 8, {
                    width: colWidths[i],
                    align: (i === 3) ? 'right' : 'left'
                  });
                });

                yPosition += 25;

                // Payment Rows
                formattedPayments.forEach((payment, index) => {
                  const rowY = yPosition + (index * 22);

                  // Check if we need a new page
                  if (rowY > 680) {
                    doc.addPage();
                    yPosition = 50;
                    const newRowY = yPosition + (index * 22);

                    // Alternating background
                    if (index % 2 === 0) {
                      doc.rect(50, newRowY, 495, 22)
                         .fillColor('#f8f9fa')
                         .fill();
                    }

                    // Row border
                    doc.rect(50, newRowY, 495, 22)
                       .strokeColor('gray')
                       .stroke();

                    doc.fontSize(9)
                       .fillColor('black');

                    doc.text(payment.transaction_date, colX[0], newRowY + 6, { width: colWidths[0] });
                    doc.text(payment.reference_no, colX[1], newRowY + 6, { width: colWidths[1] });
                    doc.text(payment.feetype, colX[2], newRowY + 6, { width: colWidths[2] });
                    doc.text(payment.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 }),
                            colX[3], newRowY + 6, { width: colWidths[3], align: 'right' });
                  } else {
                    // Alternating background
                    if (index % 2 === 0) {
                      doc.rect(50, rowY, 495, 22)
                         .fillColor('#f8f9fa')
                         .fill();
                    }

                    // Row border
                    doc.rect(50, rowY, 495, 22)
                       .strokeColor('gray')
                       .stroke();

                    doc.fontSize(9)
                       .fillColor('black');

                    doc.text(payment.transaction_date, colX[0], rowY + 6, { width: colWidths[0] });
                    doc.text(payment.reference_no, colX[1], rowY + 6, { width: colWidths[1] });
                    doc.text(payment.feetype, colX[2], rowY + 6, { width: colWidths[2] });
                    doc.text(payment.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 }),
                            colX[3], rowY + 6, { width: colWidths[3], align: 'right' });
                  }
                });

                yPosition += (formattedPayments.length * 22) + 30;
              }

              // --- ADD FOOTER TO ALL PAGES ---
              const pageCount = doc.bufferedPageRange().count;
              
              for (let i = 0; i < pageCount; i++) {
                doc.switchToPage(i);
                
                // Footer positioned at bottom of page
                const footerY = 750; // Fixed position at bottom
                
                // Footer separator line
                doc.strokeColor('lightgray')
                   .lineWidth(0.5)
                   .moveTo(50, footerY)
                   .lineTo(545, footerY)
                   .stroke();
                
                // Footer text - computer generated notice (centered)
                doc.fontSize(8)
                   .fillColor('gray')
                   .text("This is a computer-generated document and does not require a signature.",
                         50, footerY + 10, {
                           width: 495,
                           align: 'center'
                         });
                
                // Copyright and generation info (centered)
                doc.fontSize(7)
                   .fillColor('gray')
                   .text(`Generated on ${currentDate} at ${currentTime} | © Sir C R Reddy College of Engineering, Eluru District`,
                         50, footerY + 25, {
                           width: 495,
                           align: 'center'
                         });
              }

              doc.end();
            }
          );
        }
      );
    }
  );
});

// 🔹 Ignore favicon.ico request
app.get("/favicon.ico", (req, res) => res.status(204).end());

// --- PDF STYLING CONSTANTS (MUST be defined outside the route handler) ---
const BRAND_COLOR = '#000080'; // Deep Navy Blue
const ACCENT_COLOR = '#e9ecef'; // Light Gray for table header background
const BG_COLOR_EVEN = '#f8f9fa'; // Very light gray for alternating rows
const TEXT_COLOR = '#333333';
const GRAY_COLOR = '#6c757d'; // Standard Gray for details and borders
const LINE_COLOR = '#dee2e6'; // Lighter border color
const DUE_COLOR = 'red';
const FONT_BASE = "Helvetica";
const FONT_BOLD = "Helvetica-Bold";

// --- LOGO PATH ---
const LOGO_PATH = path.join(__dirname, "public", "crrengglogo.png");

// --- Helper Function (Crucial for formatting) ---
const formatAmount = (amount) => {
    // This is a common way to format to Indian Rupees with two decimal places and commas
    if (isNaN(parseFloat(amount))) return '0.00';
    return parseFloat(amount).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
};


app.get("/account-copy-fy/:userId", (req, res) => {
  const { userId } = req.params;

  pool.query(
    "SELECT reg_no, name AS full_name, course AS branch, uniqueId, section FROM students WHERE reg_no = ? OR uniqueId = ?",
    [userId, userId],
    (err, studentRows) => {
      if (err)
        return res.status(500).json({ success: false, message: "Internal Server Error - Student Query" });
      if (!studentRows.length)
        return res.status(404).json({ success: false, message: "Student not found" });

      const { reg_no, uniqueId, full_name, branch, section } = studentRows[0];

      pool.query(
        "SELECT academic_year, tuition, hostel, bus, university, semester, `library`, `fines` FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC",
        [reg_no],
        (err, feeRows) => {
          if (err)
            return res.status(500).json({ success: false, message: "Internal Server Error - Fee Query" });
          if (!feeRows.length)
            return res.status(404).json({ success: false, message: "No fee data" });

          pool.query(
            "SELECT feetype, amount, transaction_date, sbi_ref_no AS ref_no FROM sbi_uploaded_references WHERE unique_id = ? ORDER BY STR_TO_DATE(transaction_date, '%m/%d/%Y') ASC",
            [uniqueId],
            (err, payments) => {
              if (err)
                return res.status(500).json({ success: false, message: "Internal Server Error - Payments Query" });

              // --- Dynamic start year from reg_no ---
              let startYear;
              const match = reg_no.match(/^(\d{2,4})/); // match 2 or 4 digits at start
              if (match) {
                const prefix = match[1];
                if (prefix.length === 2) startYear = 2000 + parseInt(prefix); // e.g. "23" → 2023
                else startYear = parseInt(prefix); // e.g. "2026" → 2026
              } else {
                startYear = new Date().getFullYear();
              }

              // --- Group payments by FY ---
              const paymentsByFY = {};
              (payments || []).forEach(p => {
                if (!p.transaction_date) return;
                const d = new Date(p.transaction_date);
                if (isNaN(d)) return;
                const month = d.getMonth() + 1;
                const year = d.getFullYear();
                const dd = String(d.getDate()).padStart(2, "0");
                const mm = String(month).padStart(2, "0");
                const fyStart = month >= 4 ? year : year - 1;
                const fyEnd = fyStart + 1;
                const fy = `${fyStart}-${fyEnd}`;
                if (!paymentsByFY[fy]) paymentsByFY[fy] = [];
                paymentsByFY[fy].push({ ...p, parsedDate: `${dd}-${mm}-${year}` });
              });

              // --- PDF setup ---
              const uploadsDir = path.join(__dirname, "uploads");
              if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

              const doc = new PDFDocument({ margin: 50, size: "A4" });
              const filePath = path.join(uploadsDir, `${reg_no}_account_copy.pdf`);
              const stream = fs.createWriteStream(filePath);
              doc.pipe(stream);

              // --- College Header ---
              doc.fontSize(16).font("Helvetica-Bold").text("CRR COLLEGE OF ENGINEERING", { align: "center" });
              doc.fontSize(13).text("ACCOUNT COPY (Financial Year Wise)", { align: "center" });
              doc.moveDown(1.2);

              // --- Student Details Block ---
              doc.fontSize(11).font("Helvetica-Bold");
              let y = doc.y;
              const leftX = 50;
              const rightX = 320;

              doc.text(`Name: ${full_name}`, leftX, y);
              doc.text(`Course: ${branch || "-"}`, rightX, y);

              y += 15;
              doc.text(`Reg No: ${reg_no}`, leftX, y);
              doc.text(`Section: ${section || "-"}`, rightX, y);

              y += 15;
              doc.text(`Unique ID: ${uniqueId}`, leftX, y);

              doc.moveDown(1.5);

              // --- Table Setup ---
              const startX = 50;
              let startY = doc.y;
              const rowHeight = 25;
              const tableColWidths = [60, 60, 60, 60, 60, 80, 60, 60];

              const headers = ["Acad Year", "F.Y", "Prev Due", "Demand", "Amount Paid", "Bank Date", "Bank Ref No", "Amount Due"];
              doc.fontSize(9).font("Helvetica-Bold");

              let currentX = startX;
              headers.forEach((h, i) => {
                doc.rect(currentX, startY, tableColWidths[i], rowHeight).stroke();
                doc.text(h, currentX + 2, startY + 7, { width: tableColWidths[i] - 4, align: "center" });
                currentX += tableColWidths[i];
              });
              startY += rowHeight;

              // --- Table Rows ---
              doc.font("Helvetica").fontSize(9);
              let carryForwardDue = 0;

              feeRows.forEach((fee, idx) => {
                const fyStartCurrent = startYear + idx;
                const fyEndCurrent = fyStartCurrent + 1;
                const fy = `${fyStartCurrent}-${fyEndCurrent}`;
                const academicYear = idx + 1;

                const demand =
                  (parseFloat(fee.tuition) || 0) +
                  (parseFloat(fee.hostel) || 0) +
                  (parseFloat(fee.bus) || 0) +
                  (parseFloat(fee.university) || 0) +
                  (parseFloat(fee.semester) || 0) +
                  (parseFloat(fee.library) || 0) +
                  (parseFloat(fee.fines) || 0);

                const prevDue = carryForwardDue;
                let runningDue = prevDue + demand;

                const paymentsArr = paymentsByFY[fy] || [];

                if (paymentsArr.length) {
                  paymentsArr.forEach((pt, i) => {
                    currentX = startX;
                    const amountPaid = parseFloat(pt.amount) || 0;
                    runningDue -= amountPaid;

                    const rowValues = [
                      i === 0 ? academicYear : "",
                      i === 0 ? fy : "",
                      i === 0 ? prevDue : "",   // ✅ only show in first row
                      i === 0 ? demand : "",    // ✅ only show in first row
                      amountPaid,
                      pt.parsedDate,
                      pt.ref_no || "",
                      runningDue < 0 ? 0 : runningDue
                    ];

                    rowValues.forEach((val, j) => {
                      doc.rect(currentX, startY, tableColWidths[j], rowHeight).stroke();
                      doc.text(String(val), currentX + 2, startY + 7, { width: tableColWidths[j] - 4, align: "center" });
                      currentX += tableColWidths[j];
                    });
                    startY += rowHeight;
                  });
                } else {
                  currentX = startX;
                  const rowValues = [academicYear, fy, prevDue, demand, "", "", "", runningDue];
                  rowValues.forEach((val, j) => {
                    doc.rect(currentX, startY, tableColWidths[j], rowHeight).stroke();
                    doc.text(String(val), currentX + 2, startY + 7, { width: tableColWidths[j] - 4, align: "center" });
                    currentX += tableColWidths[j];
                  });
                  startY += rowHeight;
                }

                carryForwardDue = runningDue;
              });

              // --- Footer ---
              doc.moveDown(2);
              doc.fontSize(11).fillColor("red").text(`Final Outstanding Due: ${carryForwardDue}`, { align: "right" });

              doc.end();

              stream.on("finish", () => {
                res.download(filePath, `${reg_no}_account_copy.pdf`, (err) => {
                  if (err) console.error("❌ Download error:", err);
                  fs.unlink(filePath, () => {});
                });
              });
            }
          );
        }
      );
    }
  );
});

// ---------------- Fetch All Subjects Alphabetically ----------------
app.get(["/principal/all-subjects", "/correspondent/all-subjects"], (req, res) => {
  if (!validateStaff(req, res)) return;

  const query = `
    SELECT DISTINCT subcode, subname
    FROM (
      SELECT subcode, subname FROM results
      UNION
      SELECT subcode, subname FROM autonomous_results
    ) AS all_subjects
    ORDER BY subname ASC
  `;

  pool.query(query, (err, rows) => {
    if (err) {
      console.error("all-subjects error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ subjects: rows });
  });
});

// ================== HOD Backlog Routes ==================
// ---------- Helper: Build Student Filters ----------
function buildStudentFilters(query) {
    const filters = [];
    const params = [];

    if (query.year) {
        filters.push("s.year = ?");
        params.push(query.year);
    }
    if (query.course) {
        filters.push("s.course = ?");
        params.push(query.course);
    }
    if (query.section) {
        filters.push("s.section = ?");
        params.push(query.section);
    }
    return { filters, params };
}

// Helper: validate HOD
function validateHod(req, res) {
  const { staffId, dept } = req.query;
  if (!staffId || !dept) {
    res.status(400).json({ error: "HOD Staff ID and dept required" });
    return false;
  }
  // You can also check in noc.users / staff table if staffId is HOD of this dept
  return true;
}


// ========== Helper: Check if staff is HOD ==========
function isHOD(staffId) {
  // Example: Adjust this according to your DB design
  // If you already store staff roles, you can modify this check
  // For now, assume staffId starts with "HOD" or you have staff table check
  return staffId && staffId.toString().startsWith("HOD");
}

// ========== HOD Backlog Summary ==========
app.get("/hod/backlog-summary", (req, res) => {
  const { staffId } = req.query;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  const query = `
    SELECT s.reg_no,
      COALESCE(SUM(
        CASE WHEN sub_backlogs.grade IN ('F','Ab','-Ab-','NOT_COMPLETED','MP') THEN 1 ELSE 0 END
      ), 0) AS backlogs
    FROM students s
    LEFT JOIN (
      SELECT regno, grade FROM results
      UNION ALL
      SELECT regno, grade FROM autonomous_results
    ) AS sub_backlogs ON sub_backlogs.regno = s.reg_no
    ${whereClause}
    GROUP BY s.reg_no
  `;

  pool.query(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Internal Server Error" });

    let zero = 0,
      low = 0,
      high = 0;
    rows.forEach((r) => {
      const b = Number(r.backlogs) || 0;
      if (b === 0) zero++;
      else if (b <= 2) low++;
      else high++;
    });

    res.json({ zero, low, high });
  });
});

// ========== HOD Backlog Details ==========
app.get("/hod/backlog-details", (req, res) => {
  const { staffId, type } = req.query;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  const query = `
    SELECT s.reg_no,
           COALESCE(sub_backlogs.subcode, '') AS subcode,
           COALESCE(sub_backlogs.subname, '') AS subname,
           COALESCE(sub_backlogs.grade, '') AS grade
    FROM students s
    LEFT JOIN (
      SELECT regno, subcode, subname, grade FROM results
      UNION ALL
      SELECT regno, subcode, subname, grade FROM autonomous_results
    ) AS sub_backlogs ON sub_backlogs.regno = s.reg_no
    ${whereClause}
    ORDER BY s.reg_no
  `;

  pool.query(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "Internal Server Error" });

    const studentsMap = new Map();
    rows.forEach((r) => {
      if (!studentsMap.has(r.reg_no)) studentsMap.set(r.reg_no, []);
      if (["F", "Ab", "-Ab-", "NOT_COMPLETED", "MP"].includes(r.grade)) {
        studentsMap.get(r.reg_no).push({
          subcode: r.subcode,
          subname: r.subname,
          grade: r.grade,
        });
      }
    });

    const result = [];
    for (const [reg, subs] of studentsMap.entries()) {
      const count = subs.length;
      if (type === "zero" && count !== 0) continue;
      if (type === "low" && !(count >= 1 && count <= 2)) continue;
      if (type === "high" && !(count >= 3)) continue;
      result.push({ reg_no: reg, subjects: subs });
    }

    res.json({ students: result });
  });
});

// ========== HOD Subjects ==========
app.get("/hod/subjects", (req, res) => {
  const { staffId } = req.query;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const { filters, params } = buildStudentFilters(req.query);
  let whereClause = "";
  if (filters.length) {
    whereClause = "WHERE " + filters.join(" AND ");
  }

  const query = `
    SELECT DISTINCT sb.subcode, sb.subname
    FROM (
      SELECT regno, subcode, subname FROM results
      UNION ALL
      SELECT regno, subcode, subname FROM autonomous_results
    ) AS sb
    INNER JOIN students s ON s.reg_no = sb.regno
    ${whereClause}
    AND sb.subname IS NOT NULL
    ORDER BY sb.subname
  `;

  pool.query(query, params, (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json(rows.map((r) => ({ subcode: r.subcode, subname: r.subname })));
  });
});

// ========== HOD Subject Backlogs ==========
app.get("/hod/subject-backlogs", (req, res) => {
  const { staffId } = req.query;
  const subject = req.query.subject || req.query.subname;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });
  if (!subject) return res.status(400).json({ error: "Subject is required" });

  const { filters, params } = buildStudentFilters(req.query);
  const whereClause = filters.length ? "AND " + filters.join(" AND ") : "";

  const query = `
    SELECT s.reg_no AS regno, s.name, sb.subcode, sb.subname, sb.grade
    FROM (
      SELECT regno, subcode, subname, grade FROM results
      UNION ALL
      SELECT regno, subcode, subname, grade FROM autonomous_results
    ) AS sb
    INNER JOIN students s ON s.reg_no = sb.regno
    WHERE sb.subname = ?
      AND sb.grade IN ('F','Ab','-Ab-','NOT_COMPLETED','MP')
      ${whereClause}
    ORDER BY s.reg_no
  `;

  pool.query(query, [subject, ...params], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const out = rows.map((r) => ({
      regno: r.regno,
      name: r.name || "-",
      subcode: r.subcode,
      subname: r.subname,
      grade: r.grade,
    }));

    res.json(out);
  });
});

// ========== HOD Backlog PDF (No Extra Pages) ==========
app.get("/hod/backlog-pdf", (req, res) => {
  const { staffId, subcode } = req.query;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });
  if (!subcode) return res.status(400).json({ error: "subcode is required" });

  const query = `
    SELECT s.course, s.section, s.reg_no, s.name, r.grade
    FROM (
      SELECT regno, subcode, grade FROM results 
        WHERE subcode = ? AND grade NOT IN ('S','A','A+','B','C','D','E')
      UNION ALL
      SELECT regno, subcode, grade FROM autonomous_results 
        WHERE subcode = ? AND grade NOT IN ('S','A','A+','B','C','D','E')
    ) r
    INNER JOIN students s ON s.reg_no = r.regno
    ORDER BY s.course, s.section, s.reg_no
  `;

  pool.query(query, [subcode, subcode], (err, rows) => {
    if (err) return res.status(500).send("Internal Server Error");
    if (!rows || rows.length === 0)
      return res.status(404).send("✅ No backlogs found for this subject!");

    // sanitize
    rows.forEach((r) => {
      r.name = (r.name || "").replace(/\s+/g, " ").trim();
      r.course = (r.course || "").trim();
      r.section = (r.section || "").trim();
    });

    // group by section
    const sections = {};
    rows.forEach((r) => {
      const key = `${r.course}-${r.section}`.replace(/\s+/g, " ").trim();
      if (!sections[key]) sections[key] = [];
      sections[key].push(r);
    });

    const doc = new PDFDocument({ 
      margin: 50, 
      size: "A4", 
      bufferPages: true,
      autoFirstPage: true
    });
    
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=backlog_report_${subcode}.pdf`
    );
    doc.pipe(res);

    const pageHeight = doc.page.height;
    const pageWidth = doc.page.width;
    const footerSpace = 50;
    const headerHeight = 150; // Fixed header height

    const tableX = 50;
    const colWidths = { sno: 50, reg: 120, name: 280, grade: 70 };
    const tableWidth = colWidths.sno + colWidths.reg + colWidths.name + colWidths.grade;

    let currentPageHasContent = false;

    // Professional Header
    function drawHeader() {
      currentPageHasContent = true;
      
      doc.font("Helvetica-Bold")
        .fontSize(18)
        .fillColor("#1a365d")
        .text("SIR C.R. REDDY COLLEGE OF ENGINEERING", tableX, 50, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      doc.font("Helvetica")
        .fontSize(11)
        .fillColor("#2d3748")
        .text("(An Autonomous Institution)", tableX, 75, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      // Decorative line
      doc.strokeColor("#1a365d")
        .lineWidth(2)
        .moveTo(tableX, 95)
        .lineTo(tableX + tableWidth, 95)
        .stroke();
      
      doc.font("Helvetica-Bold")
        .fontSize(15)
        .fillColor("#1a365d")
        .text("BACKLOG REPORT", tableX, 110, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      // Subject info box
      doc.rect(tableX, 135, tableWidth, 25)
        .fillColor("#f7fafc")
        .strokeColor("#cbd5e0")
        .lineWidth(1)
        .fillAndStroke();
      
      doc.font("Helvetica-Bold")
        .fontSize(11)
        .fillColor("#2d3748")
        .text(`Subject Code: ${subcode}`, tableX, 143, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      doc.y = 170; // Set fixed Y position after header
    }

    function needsNewPage(requiredSpace) {
      return doc.y + requiredSpace > pageHeight - footerSpace;
    }

    function addNewPage() {
      doc.addPage();
      currentPageHasContent = false;
      doc.y = 50; // Start from top of new page
    }

    function drawSectionHeader(text, total) {
      const sectionHeight = 35;
      
      // Check if section header fits
      if (needsNewPage(sectionHeight + 30)) {
        addNewPage();
      }
      
      currentPageHasContent = true;
      
      // Section header box
      const boxY = doc.y;
      doc.rect(tableX, boxY, tableWidth, sectionHeight)
        .fillColor("#edf2f7")
        .strokeColor("#a0aec0")
        .lineWidth(1)
        .fillAndStroke();
      
      const sectionText = `${text} (Total Backlogs: ${total})`;
      
      doc.font("Helvetica-Bold")
        .fontSize(12)
        .fillColor("#1a365d")
        .text(sectionText, tableX, boxY + 10, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      doc.y = boxY + sectionHeight + 5;
    }

    function drawTableHeader() {
      const headerHeight = 25;
      
      // Check if table header fits
      if (needsNewPage(headerHeight + 20)) {
        addNewPage();
        return false; // Signal that we need to redraw section header
      }
      
      currentPageHasContent = true;
      const y = doc.y;
      
      // Header background
      doc.rect(tableX, y, tableWidth, headerHeight)
        .fillColor("#2d3748")
        .fill();
      
      // Header borders  
      doc.rect(tableX, y, tableWidth, headerHeight)
        .strokeColor("#1a202c")
        .lineWidth(1)
        .stroke();
      
      // Column separators
      let x = tableX;
      [colWidths.sno, colWidths.reg, colWidths.name].forEach(width => {
        x += width;
        doc.strokeColor("#4a5568")
          .lineWidth(0.5)
          .moveTo(x, y)
          .lineTo(x, y + headerHeight)
          .stroke();
      });
      
      // Header text
      doc.font("Helvetica-Bold")
        .fontSize(10)
        .fillColor("white");
      
      doc.text("S.No", tableX, y + 8, { 
        width: colWidths.sno, 
        align: "center",
        lineBreak: false
      });
      
      doc.text("Registration No", tableX + colWidths.sno, y + 8, { 
        width: colWidths.reg, 
        align: "center",
        lineBreak: false
      });
      
      doc.text("Student Name", tableX + colWidths.sno + colWidths.reg, y + 8, { 
        width: colWidths.name, 
        align: "center",
        lineBreak: false
      });
      
      doc.text("Grade", tableX + colWidths.sno + colWidths.reg + colWidths.name, y + 8, { 
        width: colWidths.grade, 
        align: "center",
        lineBreak: false
      });
      
      doc.y = y + headerHeight;
      return true;
    }

    function drawTableRow(stu, index, isEven) {
      const rowH = 20;
      
      // Check if row fits
      if (needsNewPage(rowH)) {
        return false; // Signal that we need new page
      }
      
      currentPageHasContent = true;
      const y = doc.y;
      
      // Alternating row colors
      if (isEven) {
        doc.rect(tableX, y, tableWidth, rowH)
          .fillColor("#f8f9fa")
          .fill();
      }
      
      // Row border
      doc.rect(tableX, y, tableWidth, rowH)
        .strokeColor("#e2e8f0")
        .lineWidth(0.5)
        .stroke();
      
      // Column separators
      let x = tableX;
      [colWidths.sno, colWidths.reg, colWidths.name].forEach(width => {
        x += width;
        doc.strokeColor("#e2e8f0")
          .lineWidth(0.3)
          .moveTo(x, y)
          .lineTo(x, y + rowH)
          .stroke();
      });
      
      // Grade color coding
      let gradeColor = "#2d3748";
      if (stu.grade === "F" || stu.grade === "Ab") gradeColor = "#e53e3e";
      else if (stu.grade === "RA") gradeColor = "#d69e2e";
      
      // Row data
      doc.font("Helvetica")
        .fontSize(9)
        .fillColor("#2d3748");
      
      doc.text((index + 1).toString(), tableX, y + 5, { 
        width: colWidths.sno, 
        align: "center",
        lineBreak: false
      });
      
      doc.text(stu.reg_no || "N/A", tableX + colWidths.sno, y + 5, { 
        width: colWidths.reg, 
        align: "center",
        lineBreak: false
      });
      
      doc.text(stu.name || "N/A", tableX + colWidths.sno + colWidths.reg + 5, y + 5, { 
        width: colWidths.name - 10, 
        align: "left",
        lineBreak: false
      });
      
      doc.font("Helvetica-Bold")
        .fontSize(10)
        .fillColor(gradeColor)
        .text(stu.grade || "N/A", tableX + colWidths.sno + colWidths.reg + colWidths.name, y + 5, { 
          width: colWidths.grade, 
          align: "center",
          lineBreak: false
        });
      
      doc.y = y + rowH;
      return true;
    }

    function drawGrandTotal(grandTotal) {
      const totalHeight = 40;
      
      // Check if grand total fits
      if (needsNewPage(totalHeight + 20)) {
        addNewPage();
      }
      
      currentPageHasContent = true;
      
      doc.y += 15; // Add some spacing
      
      const totalBoxY = doc.y;
      
      doc.rect(tableX, totalBoxY, tableWidth, totalHeight)
        .fillColor("#f0fff4")
        .strokeColor("#38a169")
        .lineWidth(2)
        .fillAndStroke();
      
      doc.font("Helvetica-Bold")
        .fontSize(14)
        .fillColor("#1a365d")
        .text(`GRAND TOTAL BACKLOGS: ${grandTotal}`, tableX, totalBoxY + 12, { 
          width: tableWidth, 
          align: "center",
          lineBreak: false
        });
      
      doc.y = totalBoxY + totalHeight;
    }

    // Start drawing
    drawHeader();
    
    let grandTotal = 0;
    const sectionKeys = Object.keys(sections);

    for (let secIndex = 0; secIndex < sectionKeys.length; secIndex++) {
      const secKey = sectionKeys[secIndex];
      const students = sections[secKey];
      grandTotal += students.length;
      
      // Draw section header
      drawSectionHeader(secKey, students.length);
      
      // Draw table header, retry if page break occurred
      let headerDrawn = drawTableHeader();
      if (!headerDrawn) {
        drawSectionHeader(secKey, students.length);
        drawTableHeader();
      }
      
      // Draw students
      for (let i = 0; i < students.length; i++) {
        const stu = students[i];
        let rowDrawn = drawTableRow(stu, i, i % 2 === 0);
        
        if (!rowDrawn) {
          // Need new page, redraw section header and table header
          addNewPage();
          drawSectionHeader(secKey + " (continued)", students.length);
          drawTableHeader();
          drawTableRow(stu, i, i % 2 === 0);
        }
      }
    }

    // Draw grand total
    drawGrandTotal(grandTotal);

    // Add footers to all pages (only pages with content)
    const pages = doc.bufferedPageRange();
    const generatedOn = new Date().toLocaleString("en-IN", { 
      timeZone: "Asia/Kolkata",
      year: "numeric",
      month: "2-digit", 
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });

    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      const y = pageHeight - 30;
      
      // Footer line
      doc.strokeColor("#cbd5e0")
        .lineWidth(0.5)
        .moveTo(50, y - 5)
        .lineTo(pageWidth - 50, y - 5)
        .stroke();
      
      doc.font("Helvetica")
        .fontSize(8)
        .fillColor("#718096")
        .text(`Generated on: ${generatedOn} | System: Academic Management`, 50, y, { align: "left" });
      
      doc.text(`Page ${i + 1} of ${pages.count}`, 50, y, { align: "right" });
    }

    // Finalize document
    doc.end();
  });
});


// ---------------- HOD Fetch All Subjects Alphabetically ----------------
app.get("/hod/all-subjects", (req, res) => {
  const { staffId } = req.query;
  if (!isHOD(staffId)) return res.status(400).json({ error: "Invalid Staff ID" });

  const query = `
    SELECT DISTINCT subcode, subname
    FROM (
      SELECT subcode, subname FROM results
      UNION
      SELECT subcode, subname FROM autonomous_results
    ) AS all_subjects
    ORDER BY subname ASC
  `;

  pool.query(query, (err, rows) => {
    if (err) {
      console.error("hod/all-subjects error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ subjects: rows });
  });
});

//accounts upload fee route
app.post("/upload-fee-structure", upload.single("file"), (req, res) => {
  if (!req.file)
    return res.status(400).json({ success: false, message: "No file uploaded" });

  const filePath = req.file.path;
  const results = [];

  console.log("📂 Upload started:", filePath);

  // Detect CSV separator automatically
  const fileContent = fs.readFileSync(filePath, "utf8");
  const firstLine = fileContent.split(/\r?\n/)[0];
  let separator = ",";
  if (firstLine.includes("\t")) separator = "\t";
  else if (firstLine.includes(";")) separator = ";";

  console.log("🧠 Detected Separator:", JSON.stringify(separator));

  fs.createReadStream(filePath)
    .pipe(
      csv({
        separator,
        mapHeaders: ({ header }) => header.replace(/^\uFEFF/, "").trim(),
      })
    )
    .on("headers", (headers) => {
      console.log("🧩 Detected Headers:", headers);
    })
    .on("data", (row) => results.push(row))
    .on("end", () => {
      fs.unlinkSync(filePath);
      console.log("🧾 Total rows parsed:", results.length);

      // ✅ UPSERT (insert or update existing)
      const insertQuery = `
        INSERT INTO student_fee_structure 
        (reg_no, academic_year, tuition, university, bus, hostel, semester, crt_fee, library, other_fee, fines)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          tuition = IF(VALUES(tuition) > 0, VALUES(tuition), tuition),
          university = IF(VALUES(university) > 0, VALUES(university), university),
          bus = IF(VALUES(bus) > 0, VALUES(bus), bus),
          hostel = IF(VALUES(hostel) > 0, VALUES(hostel), hostel),
          semester = IF(VALUES(semester) > 0, VALUES(semester), semester),
          crt_fee = IF(VALUES(crt_fee) > 0, VALUES(crt_fee), crt_fee),
          library = IF(VALUES(library) > 0, VALUES(library), library),
          other_fee = IF(VALUES(other_fee) > 0, VALUES(other_fee), other_fee),
          fines = IF(VALUES(fines) > 0, VALUES(fines), fines)
      `;

      let insertedCount = 0;
      let processedCount = 0;

      results.forEach((r, index) => {
        const reg_no = r["REG.NO"]?.trim();
        const year = parseInt(r["YEAR"]) || 0;
        const tuition = parseFloat(r["TUITION FEE PAYABLE"]) || 0;
        const university = parseFloat(r["UNIVERSITY FEE PAYABLE"]) || 0;
        const bus = parseFloat(r["BUS FEE PAYABLE"]) || 0;
        const hostel = parseFloat(r["HOSTEL FEE PAYABLE"]) || 0;
        const semester = parseFloat(r["SEMESTER FEE"]) || 0;
        const crt_fee = parseFloat(r["CRT FEE"]) || 0;
        const library = parseFloat(r["LIBRARY FEE"]) || 0;
        const other_fee = parseFloat(r["OTHER FEE PAYABLE"]) || 0;
        const fines = parseFloat(r["FINES"]) || 0;

        if (!reg_no) {
          console.warn(`⚠️ Skipped row ${index + 1} (missing REG.NO)`);
          processedCount++;
          return;
        }

        pool.query(
          insertQuery,
          [
            reg_no,
            year,
            tuition,
            university,
            bus,
            hostel,
            semester,
            crt_fee,
            library,
            other_fee,
            fines,
          ],
          (err, result) => {
            processedCount++;
            if (err) {
              console.error(`❌ Row ${index + 1} error:`, err.message);
            } else {
              insertedCount++;
              console.log(`✅ Row ${index + 1} processed (${reg_no}, Year ${year})`);
            }

            if (processedCount === results.length) {
              console.log(`✅ Completed ${insertedCount}/${results.length} records.`);
              res.json({
                success: true,
                message: `Processed ${insertedCount} of ${results.length} records successfully.`,
              });
            }
          }
        );
      });
    })
    .on("error", (err) => {
      console.error("❌ CSV parse error:", err);
      res.status(500).json({ success: false, message: "Error processing CSV file." });
    });
});
