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
  const { userId, payments } = req.body;

  if (!userId || !Array.isArray(payments)) {
    return res.status(400).json({ success: false, message: "Invalid data" });
  }

  const values = [];
  const checkMatches = [];

  for (const p of payments) {
    const du = p.du?.trim();
    const amt = parseFloat(p.amount);
    const feeType = p.type;

    values.push([userId, feeType, du, amt]);

    checkMatches.push(new Promise(resolve => {
      connection.query(
        "SELECT * FROM sbi_uploaded_references WHERE sbi_ref_no = ? AND amount = ?",
        [du, amt],
        (err, results) => {
          if (err) return resolve([du, false]);
          resolve([du, results.length > 0]);
        }
      );
    }));
  }
  Promise.all(checkMatches).then(matchResults => {
    const matchMap = Object.fromEntries(matchResults);

    const finalValues = values.map(([userId, type, du, amt]) => {
      const isMatched = matchMap[du] ? 1 : 0;
      return [userId, type, du, amt, isMatched];
    });

const sql = `
  INSERT INTO student_fee_payments (userId, fee_type, sbi_ref_no, amount_paid, matched)
  VALUES ?
  ON DUPLICATE KEY UPDATE
    sbi_ref_no = VALUES(sbi_ref_no),
    amount_paid = VALUES(amount_paid),
    matched = VALUES(matched),
    matched_on = IF(matched = 0 AND VALUES(matched) = 1, NOW(), matched_on)
`;
    connection.query(sql, [finalValues], (err2) => {
      if (err2) {
        console.error("Insert error:", err2);
        return res.status(500).json({ success: false, message: "DB error" });
      }

      res.json({ success: true, message: "DU entries verified and stored successfully." });
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

    connection.query(`
      SELECT * FROM student_fee_structure 
      WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1
    `, [reg_no], (err2, feeRows) => {
      if (err2 || feeRows.length === 0) return res.status(400).json({ success: false });

      const feeStructure = feeRows[0];

      // ✅ Fix: use userId and correct column 'amount_paid'
      connection.query(`
        SELECT fee_type, SUM(amount_paid) AS paid 
        FROM student_fee_payments
        WHERE userId = ? AND matched = 1
        GROUP BY fee_type
      `, [userId], (err3, paidRows) => {
        if (err3) return res.status(500).json({ success: false });

        const paidMap = {};
        paidRows.forEach(row => {
          paidMap[row.fee_type.toLowerCase()] = parseFloat(row.paid);
        });

        const expected = {
          tuition: parseFloat(feeStructure.tuition) || 0,
          hostel: parseFloat(feeStructure.hostel) || 0,
          bus: parseFloat(feeStructure.bus) || 0,
          university: parseFloat(feeStructure.university) || 0,
          semester: parseFloat(feeStructure.semester) || 0,
          library: parseFloat(feeStructure.library) || 0,
          fines: parseFloat(feeStructure.fines) || 0
        };

        const remaining = {};
        for (const key in expected) {
          remaining[key] = expected[key] - (paidMap[key] || 0);
        }

        return res.json({
          success: true,
          reg_no,
          expected,
          paid: paidMap,
          remaining
        });
      });
    });
  });
});



//logic for noc verification in staff page
app.get('/staff/verify-noc/:reg_no', (req, res) => {
  const { reg_no } = req.params;

  // Step 1: Get userId from reg_no
  connection.query('SELECT userId FROM students WHERE reg_no = ?', [reg_no], (err, studentRows) => {
    if (err || studentRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const { userId } = studentRows[0];

    // Step 2: Get latest fee structure for this student
    connection.query(
      'SELECT * FROM student_fee_structure WHERE reg_no = ? ORDER BY updated_at DESC LIMIT 1',
      [reg_no],
      (err2, feeRows) => {
        if (err2 || feeRows.length === 0) {
          return res.status(400).json({ success: false, message: 'Fee structure not found' });
        }
        const feeStructure = feeRows[0];
        // Step 3: Get matched paid amounts
        connection.query(
          `SELECT fee_type, SUM(amount_paid) AS paid 
           FROM student_fee_payments 
           WHERE userId = ? AND matched = 1 
           GROUP BY fee_type`,
          [userId],
          (err3, paidRows) => {
            if (err3) return res.status(500).json({ success: false });
            const paidMap = {};
            paidRows.forEach(row => paidMap[row.fee_type] = parseFloat(row.paid));
            // Step 4: Fetch total fines
            connection.query(
              'SELECT SUM(amount) AS fine FROM fines WHERE userId = ?',
              [userId],
              (err4, fineRes) => {
                if (err4) return res.status(500).json({ success: false });

                const fineAmount = parseFloat(fineRes[0].fine) || 0;

                const expected = {
                  tuition: parseFloat(feeStructure.tuition) || 0,
                  hostel: parseFloat(feeStructure.hostel) || 0,
                  bus: parseFloat(feeStructure.bus) || 0,
                  university: parseFloat(feeStructure.university) || 0,
                  semester: parseFloat(feeStructure.semester) || 0,
                  library: parseFloat(feeStructure.library) || 0,
                  fines: fineAmount
                };
                // Step 5: Compare expected vs paid
                for (const key in expected) {
                  const remaining = expected[key] - (paidMap[key] || 0);
                  if (remaining > 0) {
                    return res.json({ success: true, eligible: false, userId, reg_no });
                  }
                }
                return res.json({ success: true, eligible: true, userId, reg_no });
              }
            );
          }
        );
      }
    );
  });
});
//logic for the fee upadate by staff
// ✅ Staff updates fee structure for a student by reg_no
app.post('/update-fee-structure', (req, res) => {
  const {
    reg_no,
    academic_year,
    tuition, hostel, bus,
    university, semester, library
  } = req.body;

  if (!reg_no || !academic_year) {
    return res.status(400).json({
      success: false,
      message: "Registration number or academic year missing."
    });
  }

  const fees = {
    tuition: parseFloat(tuition) || 0,
    hostel: parseFloat(hostel) || 0,
    bus: parseFloat(bus) || 0,
    university: parseFloat(university) || 0,
    semester: parseFloat(semester) || 0,
    library: parseFloat(library) || 0
  };

  console.log("📥 Fee update for:", reg_no, "Year:", academic_year);
  console.log("📄 Fee values:", fees);

  // ✅ One smart query: insert or update automatically
  const query = `
    INSERT INTO student_fee_structure 
      (reg_no, academic_year, tuition, hostel, bus, university, semester, library, updated_on)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ON DUPLICATE KEY UPDATE 
      tuition = VALUES(tuition),
      hostel = VALUES(hostel),
      bus = VALUES(bus),
      university = VALUES(university),
      semester = VALUES(semester),
      library = VALUES(library),
      updated_on = NOW()
  `;

  const values = [
    reg_no,
    academic_year,
    fees.tuition,
    fees.hostel,
    fees.bus,
    fees.university,
    fees.semester,
    fees.library
  ];

  connection.query(query, values, (err2) => {
    if (err2) {
      console.error("❌ MySQL Error:", err2.sqlMessage);
      return res.status(500).json({ success: false, message: "Fee insert/update failed" });
    }

    res.json({
      success: true,
      message: `✅ Fee updated for ${reg_no} (Year ${academic_year})`
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
                const qrLink = `https://crr-noc.onrender.com/fee-status/${userId}`;
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
              }
            );
          });
        }
      );
    }
  );
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
