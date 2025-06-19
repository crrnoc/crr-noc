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
const router = express.Router();
const adminRoutes = require("./admin"); 
const app = express();
const PORT = 3000;
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const pdfParse = require("pdf-parse"); 
require('dotenv').config();

const logoBase64 = fs.readFileSync('./public/crrengglogo.png', { encoding: 'base64' }); // rename your image to logo.png in public
// Configure the email transporter (use your App Password here)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'crrenoccertificate@gmail.com',
    pass: 'lvwv dbqt ukfc sviv' // Replace with actual app password
  }
});
// ✅ Middlewares (used only once)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'sircrrengg@123',
  resave: false,
  saveUninitialized: true
}));

// ✅ Static files
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // for previews

// ✅ MySQL connection
// 🟢 Load .env at the top

// Ensure uploads folder exists (handles Render crash)
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ✅ Use MySQL connection from .env
const connection = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});


connection.connect((err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.stack);
  } else {
    console.log('✅ Connected to MySQL database');
  }
});


// ✅ Admin routes
app.use("/admin", adminRoutes);

// 🔐 Login route
// 🔐 Login route

app.post('/login', (req, res) => {
  const { userId, password, role } = req.body;

  // Step 1: Get user by ID and role (not by password!)
  connection.query(
    'SELECT * FROM users WHERE userId = ? AND role = ?',
    [userId, role],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ success: false, message: 'Invalid credentials or role mismatch' });
      }

      const user = results[0];

      // Step 2: Compare input password with hashed password
      bcrypt.compare(password, user.password, (err2, isMatch) => {
        if (err2 || !isMatch) {
          return res.status(401).json({ success: false, message: 'Incorrect password' });
        }

        // ✅ Password correct
        req.session.userId = userId;
        req.session.role = role;

        let redirectTo = "";
        if (role === "student") redirectTo = `/student/${userId}`;
        else if (role === "staff") redirectTo = `/staff/${userId}`;
        else if (role === "admin") redirectTo = `/admin/dashboard`;

        res.status(200).json({
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
//email otp
// Store OTPs temporarily in memory (for demo purpose only)
const otpMap = new Map();

// 1️⃣ Send OTP
app.post('/send-otp', (req, res) => {
  const { userId, email } = req.body;

  connection.query('SELECT email FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err || results.length === 0 || results[0].email !== email) {
      return res.json({ success: false, message: "User ID and email don't match." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    otpMap.set(userId, otp.toString());

    const mailOptions = {
      from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
      to: email,
      subject: "Your OTP for Password Reset",
      text: `Your OTP is ${otp}. It will expire in 10 minutes.`,
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) return res.json({ success: false, message: "Failed to send email." });

      // Optionally, set timeout to auto-delete OTP
      setTimeout(() => otpMap.delete(userId), 10 * 60 * 1000);

      res.json({ success: true });
    });
  });
});

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
    const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 = salt rounds

    connection.query(
      'UPDATE users SET password = ? WHERE userId = ?',
      [hashedPassword, userId],
      (err) => {
        if (err) return res.json({ success: false });
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

  connection.query('SELECT * FROM students WHERE userId = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    res.json(results[0]);
  });
});

// ✏️ Update student profile
app.post('/editprofile', (req, res) => {
  const { userId, name, dob, year, course, semester, unique_id, aadhar, mobile, email } = req.body;

  console.log("Received Update Data:", req.body); // 👀 Log incoming data

  const sql = `
    UPDATE students 
   SET name=?, dob=?, year=?, course=?, semester=?, unique_id=?, aadhar_no=?, mobile_no=?, email=?
    WHERE userId=?
  `;

  connection.query(sql, [name, dob, year, course, semester, unique_id, aadhar, mobile, email, userId], (err, result) => {
    if (err) {
      console.error("❌ SQL Update Error:", err.message);
      return res.status(500).json({ message: "Failed to update profile", error: err.message });
    }

    res.json({ message: "Profile updated successfully" });
  });
});

// 🚀 Start server (only once!)
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

//message route for staff

app.post('/send-notification', (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message) {
    return res.status(400).json({ success: false, message: "Missing userId or message" });
  }

  // 1️⃣ Get the email from students table
  const studentQuery = 'SELECT email, name FROM students WHERE userId = ?';
  connection.query(studentQuery, [userId], (err, studentResults) => {
    if (err || studentResults.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    const student = studentResults[0];
    const studentEmail = student.email;
    const studentName = student.name;

    // 2️⃣ Send email
    const mailOptions = {
      from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
      to: studentEmail,
      subject: "📢 Important Notification from CRR NOC Team",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #003366;">Sir C R Reddy College of Engineering</h2>
          <p>Dear <strong>${studentName}</strong>,</p>
          <p>${message}</p>
          <br>
          <p style="color: #555;">Best regards,<br><strong>CRR NOC Team</strong></p>
        </div>
      `
    };

    transporter.sendMail(mailOptions, (err2) => {
      if (err2) {
        console.error("Email sending failed:", err2);
        return res.status(500).json({ success: false, message: "Failed to send email" });
      }

      // 3️⃣ Save in notifications table
      const query = 'INSERT INTO notifications (userId, message) VALUES (?, ?)';
      connection.query(query, [userId, message], (err3) => {
        if (err3) {
          console.error("Notification DB Error:", err3);
          return res.status(500).json({ success: false, message: "Notification sent but DB error" });
        }

        res.json({ success: true, message: "✅ Notification sent and email delivered!" });
      });
    });
  });
});

// Get notifications for a specific user
app.get('/notifications/:userId', (req, res) => {
  const { userId } = req.params;

  const query = 'SELECT message, date_sent FROM notifications WHERE userId = ? ORDER BY date_sent DESC';
  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching notifications:", err);
      return res.status(500).json({ success: false, message: "Error retrieving notifications" });
    }

    res.json({ success: true, notifications: results });
  });
});
// delete notifications automatically
const cron = require('node-cron');

// Run every 3 days at 2:00 AM
cron.schedule('0 2 */3 * *', () => {
  const query = 'DELETE FROM notifications WHERE date_sent < NOW() - INTERVAL 3 DAY';
  connection.query(query, (err, result) => {
    if (err) {
      console.error('❌ Failed to delete old notifications:', err);
    } else {
      console.log(`✅ Deleted ${result.affectedRows} old notifications.`);
    }
  });
});
//fine impose
app.post('/impose-fine', (req, res) => {
  const { userId, amount, reason, staffId, academic_year } = req.body;

  if (!userId || !reason || !amount || !staffId || !academic_year) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  const query = `
    INSERT INTO fines (userId, amount, reason, staffId, academic_year)
    VALUES (?, ?, ?, ?, ?)
  `;
  const values = [userId, amount, reason, staffId, academic_year];

  connection.query(query, values, (err, result) => {
    if (err) {
      console.error("❌ Error inserting fine:", err);
      return res.status(500).json({ success: false, message: "Failed to insert fine" });
    }

    const message = `💸 Fine of ₹${amount} for Year ${academic_year} imposed by Staff ID: ${staffId}. Reason: ${reason}`;
    connection.query('INSERT INTO notifications (userId, message) VALUES (?, ?)', [userId, message], (err2) => {
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
  connection.query('SELECT SUM(amount) AS totalFine FROM fines WHERE userId = ?', [userId], (err, results) => {
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
    const [structureRows] = await db.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ?',
      [regNo]
    );

    if (structureRows.length === 0) {
      return res.json({ success: false, message: "Fee structure not found." });
    }

    const structure = structureRows[0];

    // 2. Get total paid per category
    const [paidRows] = await db.query(
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

  connection.query(sql, [userId], (err, results) => {
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

  const values = [];
  const checkMatches = [];

  for (const p of payments) {
    const du = p.du?.trim();
    const amt = parseFloat(p.amount);
    const feeType = p.type;

    // 🧠 Push with academic_year & dummy matched (0 by default)
    values.push([userId, feeType, du, amt, academic_year, 0]);

    // Check match against SBI data
    checkMatches.push(
      new Promise(resolve => {
        connection.query(
          "SELECT * FROM sbi_uploaded_references WHERE sbi_ref_no = ? AND amount = ?",
          [du, amt],
          (err, results) => {
            if (err) return resolve([du, false]);
            resolve([du, results.length > 0]);
          }
        );
      })
    );
  }

  Promise.all(checkMatches).then(matchResults => {
    const matchMap = Object.fromEntries(matchResults);

    // ✅ Replace matched=0 with actual match result
    const finalValues = values.map(([userId, type, du, amt, year, matched]) => {
      const isMatched = matchMap[du] ? 1 : 0;
      return [userId, type, du, amt, year, isMatched];
    });

    const sql = `
      INSERT INTO student_fee_payments (userId, fee_type, sbi_ref_no, amount_paid, academic_year, matched)
      VALUES ?
      ON DUPLICATE KEY UPDATE
        sbi_ref_no = VALUES(sbi_ref_no),
        amount_paid = VALUES(amount_paid),
        matched = VALUES(matched),
        academic_year = VALUES(academic_year),
        matched_on = IF(matched = 0 AND VALUES(matched) = 1, NOW(), matched_on)
    `;

    connection.query(sql, [finalValues], (err2) => {
      if (err2) {
        console.error("❌ Insert error:", err2);
        return res.status(500).json({ success: false, message: "DB error" });
      }

      res.json({ success: true, message: "✅ DU entries verified and stored successfully." });
    });
  });
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

  connection.query(sql, [reg_no], (err, results) => {
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

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(500).json({ success: false });
    }

    const reg_no = studentRows[0].reg_no;

    // 1. Get latest fee structure
    connection.query(`
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
      connection.query(`
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
app.post('/admin/upload-sbi', upload.single('sbiFile'), (req, res) => {
  const filePath = path.join(__dirname, req.file.path);

  const lines = fs.readFileSync(filePath, 'utf-8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line !== '');

  const formatted = lines
    .map(row => row.split(','))
    .filter(([ref, amount]) => ref && amount)
    .map(([ref, amount]) => [ref.trim(), parseFloat(amount.trim())]);

  const query = `INSERT INTO sbi_uploaded_references (sbi_ref_no, amount) VALUES ?`;

  connection.query(query, [formatted], (err) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).json({ success: false, message: 'Upload failed.' });
    }

    // Match after insert
    connection.query(`
      UPDATE student_fee_payments p
      JOIN sbi_uploaded_references s ON p.sbi_ref_no = s.sbi_ref_no AND p.amount_paid = s.amount
      SET p.matched = 1, p.matched_on = NOW()
      WHERE p.matched = 0
    `, (err2) => {
      if (err2) {
        console.error('Match error:', err2);
        return res.status(500).json({ success: false, message: 'Matching failed.' });
      }

      res.json({ success: true, message: 'SBI DU numbers uploaded and matched with amount.' });
    });
  });
});
app.get('/admin/matches', (req, res) => {
  connection.query('SELECT * FROM student_fee_payments', (err, results) => {
    if (err) {
      console.error('Error fetching matches:', err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});
app.get('/admin/noc-status', (req, res) => {
  connection.query('SELECT userId, reg_no FROM students', (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no } = student;

      return new Promise(resolve => {
        // 1️⃣ Get latest fee structure
        connection.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, eligible: false });

            const fees = feeRows[0];
            // 2️⃣ Get verified paid fees
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 
               GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));
                // 3️⃣ Get fines
                connection.query(
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
                    // ✅ Check remaining
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

app.get("/fee-status/:userId", (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) return res.status(500).json({ success: false });

    const reg_no = studentRows[0].reg_no;

    // 1. Get ALL fee structures by year
    connection.query(`
      SELECT * FROM student_fee_structure 
      WHERE reg_no = ?
    `, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) return res.status(400).json({ success: false });

      // 2. Get ALL payments by user grouped by year and fee_type
      connection.query(`
        SELECT academic_year, fee_type, SUM(amount_paid) AS paid
        FROM student_fee_payments
        WHERE userId = ? AND matched = 1
        GROUP BY academic_year, fee_type
      `, [userId], (err3, paidRows) => {
        if (err3) return res.status(500).json({ success: false });

        const paidMap = {};
        paidRows.forEach(row => {
          const year = row.academic_year;
          const type = row.fee_type.toLowerCase();
          if (!paidMap[year]) paidMap[year] = {};
          paidMap[year][type] = parseFloat(row.paid);
        });

        const years = {};

        feeRows.forEach(row => {
          const year = row.academic_year;
          const expected = {
            tuition: parseFloat(row.tuition) || 0,
            hostel: parseFloat(row.hostel) || 0,
            bus: parseFloat(row.bus) || 0,
            university: parseFloat(row.university) || 0,
            semester: parseFloat(row.semester) || 0,
            library: parseFloat(row.library) || 0,
            fines: parseFloat(row.fines) || 0
          };

          const paid = paidMap[year] || {};

          years[year] = {
            expected,
            paid
          };
        });

        return res.json({
          success: true,
          reg_no,
          years
        });
      });
    });
  });
});





//logic for add student in staff page
app.post('/add-student', async (req, res) => {
  const {
    userId, name, dob, reg_no, unique_id,
    year, course, semester, aadhar_no, mobile_no,
    email, password, section
  } = req.body;

  if (
    !userId || !name || !dob || !reg_no || !unique_id ||
    !year || !course || !semester || !mobile_no ||
    !email || !password
  ) {
    return res.status(400).json({ success: false, message: "Please fill all required fields" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // 1. Insert into students table
    const studentSql = `
      INSERT INTO students
      (userId, name, dob, reg_no, unique_id, year, course, semester, aadhar_no, mobile_no, email, section)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    connection.query(studentSql, [
      userId, name, dob, reg_no, unique_id, year, course, semester, aadhar_no, mobile_no, email, section
    ], (err1) => {
      if (err1) {
        console.error("Student Insert Error:", err1);
        return res.status(500).json({ success: false, message: "Failed to add student" });
      }

      // 2. Insert into users table
      const userSql = `INSERT INTO users (userid, password, role) VALUES (?, ?, 'student')`;

      connection.query(userSql, [userId, hashedPassword], (err2) => {
        if (err2) {
          console.error("User Insert Error:", err2);
          return res.status(500).json({ success: false, message: "Failed to create login" });
        }

        return res.json({ success: true, message: "✅ Student added successfully!" });
      });
    });
  } catch (err) {
    console.error("Hashing error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

//logic for the fee upadate by staff
// ✅ Staff updates fee structure for a student by reg_no
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

  connection.query(queryCheck, [reg_no, academic_year], (err, result) => {
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

   connection.query(sql, values, (err2) => {
  if (err2) {
    console.error("❌ Fee update query failed:", err2.message); // this logs the actual MySQL error
    return res.status(500).json({ success: false, message: "Query failed", error: err2.message });
  }

  res.json({ success: true, message: "✅ Year-wise fee updated successfully!" });
});

  });
});
//noc code
// ... all previous code remains unchanged

// ✅ Updated Generate NOC PDF logic (fixed hanging issue)
app.get('/generate-noc/:userId', (req, res) => {
  const { userId } = req.params;
  const academicYear = parseInt(req.query.year); // 👈 Get year from query param

  if (!academicYear || academicYear < 1 || academicYear > 4) {
    return res.status(400).json({ success: false, message: 'Invalid or missing year' });
  }

  connection.query('SELECT name, course, reg_no FROM students WHERE userId = ?', [userId], (err, studentResults) => {
    if (err || studentResults.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const student = studentResults[0];
    const reg_no = student.reg_no;

    connection.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? AND academic_year = ?',
      [reg_no, academicYear],
      (err2, feeRows) => {
        if (err2 || feeRows.length === 0) {
          return res.status(400).json({ success: false, message: 'Fee structure not found for that year' });
        }

        const feeStructure = feeRows[0];

        connection.query(
          `SELECT fee_type, SUM(amount_paid) AS paid 
           FROM student_fee_payments 
           WHERE userId = ? AND matched = 1 AND academic_year = ?
           GROUP BY fee_type`,
          [userId, academicYear],
          (err3, paidRows) => {
            if (err3) return res.status(500).json({ success: false });

            const paidMap = {};
            paidRows.forEach(row => {
              paidMap[row.fee_type] = parseFloat(row.paid);
            });

            connection.query(
              'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
              [userId, academicYear],
              (err4, fineRes) => {
                if (err4) return res.status(500).json({ success: false });

                const fineAmount = parseFloat(fineRes[0].fine) || 0;

                const expected = {
                  tuition: parseFloat(feeStructure.tuition || 0),
                  hostel: parseFloat(feeStructure.hostel || 0),
                  bus: parseFloat(feeStructure.bus || 0),
                  university: parseFloat(feeStructure.university || 0),
                  semester: parseFloat(feeStructure.semester || 0),
                  library: parseFloat(feeStructure.library || 0),
                  fines: fineAmount
                };

                const readableMap = {
                  tuition: "TUTION FEE",
                  hostel: "HOSTEL FEE",
                  bus: "BUS FEE",
                  university: "UNIVERSITY FEE",
                  semester: "EXAMINATION CELL",
                  library: "LIBRARY DUE",
                  fines: "FINE"
                };

                const status = {};
                for (const key in expected) {
                  const paid = paidMap[key] || 0;
                  const remaining = expected[key] - paid;
                  status[readableMap[key]] = remaining <= 0 ? "PAID ✅" : "NOT PAID ❌";
                }

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

                // Title
                doc.font('Times-Bold').fontSize(18).text('NO OBJECTION CERTIFICATE', {
                  align: 'center',
                  underline: true,
                });
                doc.moveDown(1.5);

                // Certificate body
                doc.font('Times-Bold').fontSize(12).text(
                  `This is to certify that Mr./Ms. ${student.name} (Roll No: ${student.reg_no}),`,
                  { align: 'justify' }
                );
                doc.moveDown(0.5);
                doc.font('Times-Roman').text(
                  `A bonafide student of ${student.course}, has the following fee details (paid/unpaid) towards the institution for   **Year ${academicYear}**.`,
                  { align: 'justify' }
                );
                doc.moveDown(1);
                doc.text(
                  `He/She has no objection from the college to appear for <exam purpose / leave purpose / higher studies / internships>`,
                  { align: 'justify' }
                );
                doc.moveDown();

                // Fee Details
                doc.font('Times-Bold').fontSize(13).text("FEE DETAILS", { align: 'center', underline: true });
                doc.moveDown();
                doc.font('Times-Roman').fontSize(12);

                const tableLeftX = 70;
                const tableRightX = 380;
                const rowHeight = 20;
                let y = doc.y;

                Object.keys(status).forEach(feeType => {
                  doc.text(feeType, tableLeftX, y);
                  doc.text(status[feeType], tableRightX, y);
                  y += rowHeight;
                });

                doc.moveDown();
                doc.text(
                  `This is a system-generated certificate and does not require a manual signature.`,
                  { align: 'center' }
                );
                doc.moveDown(1);
                doc.font('Times-Bold').text("COLLEGE STAMP", { align: 'center' });

 // QR code
const qrLink = `https://crr-noc.onrender.com/verifybyqr.html?userId=${userId}&year=${academicYear}`;

QRCode.toDataURL(qrLink, (err, qrUrl) => {
  if (err) {
    console.error("QR code generation failed", err);
    doc.end();
    return;
  }

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

  // Add footer image if exists
  const footerPath = path.join(__dirname, 'public', 'noc_footer.jpg');
  if (fs.existsSync(footerPath)) {
    const footerWidth = 500;
    const footerX = (doc.page.width - footerWidth) / 2;
    const footerY = doc.page.height - 100;

    doc.image(footerPath, footerX, footerY, {
      width: footerWidth,
      align: 'center'
    });
  }

  doc.end();

  stream.on("finish", () => {
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    res.setHeader("Content-Type", "application/pdf");

    const readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
  });
});
});
});
});
});
});

//logic for combined-noc
app.get('/generate-combined-noc/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT name, course, reg_no FROM students WHERE userId = ?', [userId], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(404).json({ success: false, message: "Student not found" });
    }

    const student = studentRows[0];
    const reg_no = student.reg_no;

    connection.query(`SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC`, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) {
        return res.status(400).json({ success: false, message: 'No fee structure found' });
      }

      const promises = feeRows.map(fee => {
        const year = fee.academic_year;

        return new Promise(resolve => {
          connection.query(
            `SELECT fee_type, SUM(amount_paid) AS paid 
             FROM student_fee_payments 
             WHERE userId = ? AND matched = 1 AND academic_year = ?
             GROUP BY fee_type`,
            [userId, year],
            (err3, paidRows) => {
              const paidMap = {};
              paidRows?.forEach(row => paidMap[row.fee_type] = parseFloat(row.paid));

              connection.query(
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

// logic for the combined noc verification by qr

app.get('/verify-combined-noc/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err, result) => {
    if (err || result.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const reg_no = result[0].reg_no;

    connection.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC',
      [reg_no],
      async (err2, feeRows) => {
        if (err2 || feeRows.length === 0) {
          return res.json({ success: false, message: "No fee structure found" });
        }

        const yearStatuses = await Promise.all(feeRows.map(fee => {
          const year = fee.academic_year;
          return new Promise(resolve => {
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS paid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 AND academic_year = ?
               GROUP BY fee_type`,
              [userId, year],
              (err3, paidRows) => {
                const paidMap = {};
                paidRows?.forEach(row => {
                  paidMap[row.fee_type.toLowerCase()] = parseFloat(row.paid);
                });

                connection.query(
                  'SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?',
                  [userId, year],
                  (err4, fineRes) => {
                    const fineAmount = parseFloat(fineRes?.[0]?.fine || 0);

                    const expected = {
                      tuition: fee.tuition || 0,
                      hostel: fee.hostel || 0,
                      bus: fee.bus || 0,
                      university: fee.university || 0,
                      semester: fee.semester || 0,
                      library: fee.library || 0,
                      fines: fineAmount
                    };

                    let allPaid = true;
                    for (const key in expected) {
                      const paid = paidMap[key] || 0;
                      if ((expected[key] - paid) > 0) {
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
        }));

        return res.json({ success: true, reg_no, yearStatuses });
      }
    );
  });
});


app.post('/api/submit-feedback', (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ success: false, message: "All fields required." });
  }

  // HTML Email for User
  const userMailOptions = {
  from: '"CRR NOC Team" <crrenoccertificate@gmail.com>',
  to: email,
  subject: "🎓 Thank You for Your Feedback",
  html: `
    <div style="font-family: Arial; padding: 20px;">
      <h2 style="color:#003366; margin-top: 0;">Sir C R Reddy College of Engineering</h2>
      <p>Hi <strong>${name}</strong>,</p>
      <p>Thank you for reaching out. We have received your feedback and will review it shortly.</p>
      <p><strong>Your message:</strong></p>
      <blockquote style="color: #444; font-style: italic;">${message}</blockquote>
      <p>Best regards,<br><strong>CRR NOC Support Team</strong></p>
    </div>
  `
};
  // Email to Admin
  const adminMailOptions = {
  from: '"CRR NOC Bot" <crrenoccertificate@gmail.com>',
  to: 'crrenoccertificate@gmail.com',
  subject: `📬 Feedback Received from ${name}`,
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

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching DU entries:", err);
      return res.status(500).json([]);
    }

    res.json(results);
  });
});
// 🧾 Get all fee entries for a user
app.get("/my-fee-entries/:userId", (req, res) => {
  const { userId } = req.params;
const sql = `SELECT id, fee_type, amount_paid, sbi_ref_no, created_at, matched 
             FROM student_fee_payments 
             WHERE userId = ? 
             ORDER BY created_at DESC`;

  connection.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Fetch error:", err);
      return res.status(500).json([]);
    }
    res.json(results);
  });
});

// ❌ Delete a specific fee entry
app.delete("/delete-fee-entry/:id", (req, res) => {
  const { id } = req.params;
  connection.query("DELETE FROM student_fee_payments WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ success: false, message: "Delete failed." });
    }
    res.json({ success: true, message: "Fee entry deleted successfully." });
  });
});
//admin filter section
app.post('/admin/noc-filter', (req, res) => {
  const { course, year, section } = req.body;

  let query = `SELECT userId, reg_no FROM students WHERE 1=1`;
  const params = [];

  if (course) {
    query += ` AND course = ?`;
    params.push(course);
  }

  if (year) {
    query += ` AND year = ?`;
    params.push(year);
  }

  if (section) {
    query += ` AND section = ?`;
    params.push(section);
  }

  connection.query(query, params, (err, students) => {
    if (err) return res.status(500).json([]);

    const checks = students.map(student => {
      const { userId, reg_no } = student;

      return new Promise(resolve => {
        connection.query(
          'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
          [reg_no],
          (err2, feeRows) => {
            if (err2 || feeRows.length === 0) return resolve({ userId, eligible: false });

            const fees = feeRows[0];
            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS totalPaid FROM student_fee_payments WHERE userId = ? AND matched = 1 GROUP BY fee_type`,
              [userId],
              (err3, paidRows) => {
                if (err3) return resolve({ userId, eligible: false });

                const paidMap = {};
                paidRows.forEach(r => paidMap[r.fee_type] = parseFloat(r.totalPaid));

                connection.query(
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

app.post('/admin/match-filter', (req, res) => {
  const { course, year, section } = req.body;

  let query = `SELECT userId FROM students WHERE 1=1`;
  const params = [];

  if (course) {
    query += ` AND course = ?`;
    params.push(course);
  }

  if (year) {
    query += ` AND year = ?`;
    params.push(year);
  }

  if (section) {
    query += ` AND section = ?`;
    params.push(section);
  }

  connection.query(query, params, (err, students) => {
    if (err) return res.status(500).json([]);

    const userIds = students.map(s => s.userId);
    if (!userIds.length) return res.json([]);

    const inClause = userIds.map(() => '?').join(',');
    const sql = `SELECT * FROM student_fee_payments WHERE userId IN (${inClause})`;

    connection.query(sql, userIds, (err2, results) => {
      if (err2) return res.status(500).json([]);
      res.json(results);
    });
  });
});


// ✅ Year-wise full fee breakdown (structure + paid + fines)
app.get('/yearwise-fee/:userId', (req, res) => {
  const { userId } = req.params;

  connection.query('SELECT reg_no FROM students WHERE userId = ?', [userId], (err1, regRes) => {
    if (err1 || regRes.length === 0) return res.status(500).json({ success: false });

    const reg_no = regRes[0].reg_no;

    connection.query(
      `SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY academic_year ASC`,
      [reg_no],
      (err2, feeRows) => {
        if (err2) return res.status(500).json({ success: false });

        if (feeRows.length === 0) return res.status(404).json({ success: false, message: "No fee data" });

        const promises = feeRows.map(fee => {
          return new Promise(resolve => {
            const year = fee.academic_year;

            connection.query(
              `SELECT fee_type, SUM(amount_paid) AS paid 
               FROM student_fee_payments 
               WHERE userId = ? AND matched = 1 AND academic_year = ?
               GROUP BY fee_type`,
              [userId, year],
              (err3, paidRows) => {
                const paidMap = {};
                paidRows?.forEach(row => paidMap[row.fee_type] = parseFloat(row.paid));

                connection.query(
                  `SELECT SUM(amount) AS fine FROM fines WHERE userId = ? AND academic_year = ?`,
                  [userId, year],
                  (err4, fineRes) => {
                    const fineAmount = parseFloat(fineRes[0]?.fine || 0);

                    resolve({
                      year,
                      structure: fee,
                      paid: paidMap,
                      fines: fineAmount
                    });
                  }
                );
              }
            );
          });
        });

        Promise.all(promises).then(data => res.json({ success: true, data }));
      }
    );
  });
});
// 🧠 Get Student Details for Removal
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
// ✅ Delete Student
app.post("/delete-student", async (req, res) => {
  const { reg_no } = req.body;

  try {
    await connection.promise().query("DELETE FROM users WHERE userid = ?", [reg_no]);
    await connection.promise().query("DELETE FROM students WHERE userId = ?", [reg_no]); // ✅ FIXED
    await connection.promise().query("DELETE FROM student_fee_structure WHERE reg_no = ?", [reg_no]);
    await connection.promise().query("DELETE FROM student_fee_payments WHERE userId = ?", [reg_no]);
    await connection.promise().query("DELETE FROM notifications WHERE userId = ?", [reg_no]);
    await connection.promise().query("DELETE FROM fines WHERE userId = ?", [reg_no]);

    res.json({ success: true, message: "Student deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ success: false, message: "Error deleting student" });
  }
});

// ✅ Filter Batch
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

// ✅ Delete Batch
app.post("/delete-batch", async (req, res) => {
  const { batchPrefix, branch } = req.body;
  try {
    const [students] = await connection.promise().query(
      "SELECT reg_no FROM students WHERE reg_no LIKE ? AND course = ?",
      [`${batchPrefix}%`, branch]
    );

    for (const student of students) {
      const reg_no = student.reg_no;
      await connection.promise().query("DELETE FROM users WHERE userid = ?", [reg_no]);
      await connection.promise().query("DELETE FROM students WHERE userId = ?", [reg_no]);
      await connection.promise().query("DELETE FROM student_fee_structure WHERE reg_no = ?", [reg_no]);
      await connection.promise().query("DELETE FROM student_fee_payments WHERE userId = ?", [reg_no]);
      await connection.promise().query("DELETE FROM notifications WHERE userId = ?", [reg_no]);
      await connection.promise().query("DELETE FROM fines WHERE userId = ?", [reg_no]);
    }

    res.json({ success: true, message: "Batch deleted successfully" });
  } catch (err) {
    console.error("Batch delete error:", err);
    res.status(500).json({ success: false, message: "Error deleting batch" });
  }
});

// result pdf upload
// 📥 Admin uploads result PDF
app.post("/admin/upload-result-pdf", upload.single("pdf"), async (req, res) => {
  try {
    const { semester } = req.body;
    if (!req.file || !semester) {
      return res.status(400).json({ message: "❌ Semester or PDF missing." });
    }

    const fileBuffer = fs.readFileSync(req.file.path);
    const data = await pdfParse(fileBuffer);
    const lines = data.text.split("\n").map(line => line.trim()).filter(Boolean);

    console.log("📝 Total lines parsed:", lines.length);

    let startReading = false;
    const insertPromises = [];

    for (let line of lines) {
      if (line.includes("SnoHtnoSubcodeSubnameInternalsGradeCredits")) {
        startReading = true;
        console.log("🔔 Found header, starting...");
        continue;
      }

      if (!startReading || line === "") continue;

      console.log("🔍 RAW LINE:", line);

      // ✅ Extract regno: exactly 10 chars like 23B81A0123
      const regnoMatch = line.match(/(\d{2}B8[A-Z0-9]{6})/);
      if (!regnoMatch) {
        console.log("❌ Could not find regno:", line);
        continue;
      }
      const regno = regnoMatch[1];

      // ✅ Extract subcode: starts with 'R' and 7 characters
      const subcodeMatch = line.match(/(R[A-Z0-9]{6})/);
      if (!subcodeMatch) {
        console.log("❌ Could not find subcode:", line);
        continue;
      }
      const subcode = subcodeMatch[1];
      const subcodeIndex = line.indexOf(subcode);
      const afterSubcode = line.slice(subcodeIndex + 7);

      // ✅ Extract subname until first digit appears
      const subnameMatch = afterSubcode.match(/^(.+?)(\d)/);
      if (!subnameMatch) {
        console.log("❌ Could not extract subname:", afterSubcode);
        continue;
      }
      const subname = subnameMatch[1].trim();

      // ✅ Extract grade and credits
      const gradeCreditsPart = afterSubcode.slice(subname.length);
      const gradeCreditMatch = gradeCreditsPart.match(/^(\d{1,3})(S|A|B|C|D|E|F|ABSENT)(\d+(\.\d+)?)/);

      if (!gradeCreditMatch) {
        console.log("❌ Could not extract grade/credits:", gradeCreditsPart);
        continue;
      }

      const gradeRaw = gradeCreditMatch[2];
      const credits = parseFloat(gradeCreditMatch[3]);
      const grade = gradeRaw === "ABSENT" ? "Ab" : gradeRaw;

      // ✅ Final INSERT using 'regno'
      const sql = `
        INSERT INTO results (regno, semester, subcode, subname, grade, credits)
        VALUES (?, ?, ?, ?, ?, ?) AS new
        ON DUPLICATE KEY UPDATE
          semester = new.semester,
          grade = new.grade,
          credits = new.credits
      `;

      console.log("📌 Parsed →", { regno, subcode, subname, grade, credits });

      insertPromises.push(new Promise(resolve => {
        connection.query(sql, [regno, semester, subcode, subname, grade, credits], (err) => {
          if (err) {
            console.error(`❌ DB Error for ${regno}:`, err.message);
          } else {
            console.log(`✅ Stored: ${regno} - ${subcode} (${grade})`);
          }
          resolve();
        });
      }));
    }

    await Promise.all(insertPromises);
    fs.unlinkSync(req.file.path);

    res.json({ success: true, message: "✅ Results uploaded and stored successfully." });

  } catch (err) {
    console.error("❌ Server error:", err);
    res.status(500).json({ message: "❌ Internal server error." });
  }
});

// result pdf upload
// 📥 Admin uploads result PDF
app.post("/admin/upload-result-pdf", upload.single("pdf"), async (req, res) => {
  try {
    const { semester } = req.body;
    if (!req.file || !semester) {
      return res.status(400).json({ success: false, message: "❌ Semester or PDF missing." });
    }

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);
    const data = await pdfParse(fileBuffer);
    const lines = data.text.split("\n").map(line => line.trim()).filter(Boolean);

    let startReading = false;
    let insertCount = 0;

    const logPath = path.join(__dirname, "parselog.txt");
    const logStream = fs.createWriteStream(logPath, { flags: "w" });

    for (const originalLine of lines) {
      if (originalLine.includes("HtnoSubcodeSubnameInternalsGradeCredits")) {
        startReading = true;
        logStream.write("🔔 Found header. Starting parse...\n");
        continue;
      }

      if (!startReading || originalLine === "") continue;

      const line = originalLine.replace(/\s/g, '').toUpperCase();

      const regnoMatch = line.match(/(\d{2}B8[A-Z0-9]{6})/);
      if (!regnoMatch) {
        logStream.write(`❌ Could not find regno: ${originalLine}\n`);
        continue;
      }
      const regno = regnoMatch[1];

      const subcodeMatch = line.match(/R[A-Z0-9]{6}/);
      if (!subcodeMatch) {
        logStream.write(`❌ Could not find subcode: ${originalLine}\n`);
        continue;
      }
      const subcode = subcodeMatch[0].substring(0, 7);

      const regYear = parseInt(subcode.slice(1, 3));
      if (isNaN(regYear) || regYear < 21) {
        logStream.write(`⏩ Skipped old regulation: ${regno} - ${subcode}\n`);
        continue;
      }

      const subcodeIndex = line.indexOf(subcode);
      const afterSubcode = line.slice(subcodeIndex + subcode.length);

      const subnameMatch = afterSubcode.match(/^(.+?)(\d)/);
      if (!subnameMatch) {
        logStream.write(`❌ Could not extract subname: ${originalLine}\n`);
        continue;
      }
      const subname = subnameMatch[1].trim();

      const gradeCreditsPart = afterSubcode.slice(subname.length);
      const gradeCreditMatch = gradeCreditsPart.match(/^(\d{1,3})([A-Z]+)(\d+(\.\d+)?)/);
      if (!gradeCreditMatch) {
        logStream.write(`❌ Could not extract grade/credits: ${originalLine}\n`);
        continue;
      }

      let gradeRaw = gradeCreditMatch[2].toUpperCase();
      const credits = parseFloat(gradeCreditMatch[3]);

      // Normalize grade
      if (["COMPLE", "COMPLETE", "COMPLETED"].includes(gradeRaw)) {
        gradeRaw = "Completed";
      } else if (gradeRaw === "ABSENT") {
        gradeRaw = "Ab";
      }

      const validGrades = ["S", "A", "B", "C", "D", "E", "F", "Ab", "Completed"];
      if (!validGrades.includes(gradeRaw)) {
        logStream.write(`❌ Invalid grade: ${gradeRaw} in ${originalLine}\n`);
        continue;
      }

      const grade = gradeRaw;

      const sql = `
        INSERT INTO results (regno, semester, subcode, subname, grade, credits)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          semester = VALUES(semester),
          grade = VALUES(grade),
          credits = VALUES(credits)
      `;

      await new Promise((resolve) => {
        connection.query(sql, [regno, semester, subcode, subname, grade, credits], (err) => {
          if (err) {
            logStream.write(`❌ DB Error for ${regno}: ${err.message}\n`);
          } else {
            insertCount++;
            logStream.write(`✅ Stored: ${regno} - ${subcode} (${grade})\n`);
          }
          resolve();
        });
      });
    }

    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    logStream.end();

    return res.json({
      success: true,
      message: `✅ Upload complete. ${insertCount} records stored. Check parselog.txt for full details.`
    });

  } catch (err) {
    console.error("❌ Server error:", err);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(500).json({ success: false, message: "❌ Internal server error." });
  }
});
