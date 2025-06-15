const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const { ObjectId } = require('mongodb');



dotenv.config();
const app = express();
const JWT_SECRET =  'your_jwt_secret_key';
const PORT =  3000;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


mongoose.connect('mongodb://127.0.0.1:27017/feedback')
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection failed", err));


const adminSchema = new mongoose.Schema({
  _id: Number,
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type:Number, 
    required: true
  },
  mail:String,
  phone: String,
});

const facultySchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  section: {
    type: String,
    required: true
  },
  subject: {
    type: String,
    required: true
  },
}, { versionKey: false });

const scheduleSchema = new mongoose.Schema({
  section: {
    type: String,
    required: true
  },
}, { versionKey: false });

const feedbackEntrySchema = new mongoose.Schema({
  faculty_id: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  subject: {
    type: String,
    required: true,
  },
  teach: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  depth: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  resource: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  assignment: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  comments: {
    type: String,
    default: ''
  },
  students_count: {  // New field to track number of students
    type: Number,
    default: 1,
    min: 1
  }
});

const facultyFeedbackSchema = new mongoose.Schema({
  feedback_id: {
    type: String,
    required: true,
    unique: true
  },
  entries: [feedbackEntrySchema]
},{versionKey: false});

const Admin = mongoose.model('Admin', adminSchema, 'admin');
const Faculty = mongoose.model('Faculty', facultySchema, 'faculty_credentials');
const Schedule = mongoose.model('Schedule', scheduleSchema, 'scheduleFeedback');
const FacultyFeedback = mongoose.model('FacultyFeedback', facultyFeedbackSchema, 'faculty_feedback');


const authenticateToken = (req, res, next) => {
  const token = req.cookies.adminJwt || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  
  if (!token) {
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

const authenticateFaculty = async (req, res, next) => {
  try {
    const token = req.cookies.facultyJwt || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
    
    if (!token) {
      return res.sendFile(path.join(__dirname, 'public', 'facultylogin.html'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.role !== 'faculty') {
      return res.status(403).sendFile(path.join(__dirname, 'public', 'facultylogin.html'));
    }
    
    const faculty = await Faculty.findById(decoded.id);
    if (!faculty) {
      return res.status(401).json({ success: false, message: 'Invalid faculty account.' });
    }
    
    req.faculty = {
      id: faculty._id,
      user: faculty.user,
      section: faculty.section,
      subject: faculty.subject,
      role: 'faculty'
    };
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token.' });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired.' });
    } else {
      console.error('Authentication error:', error);
      return res.status(500).json({ success: false, message: 'Authentication failed.', error: error.message });
    }
  }
};

// Admin Routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/adminhome', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'adminhome.html'));
});

app.get('/admin/schedule', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'schedule.html'));
});

app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    
    const adminUser = await Admin.findOne({ username });
    
    if (!adminUser) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check if password is stored as number or string
    let isValidPassword = false;
    if (typeof adminUser.password === 'number') {
      isValidPassword = adminUser.password === parseInt(password);
    } else {
      isValidPassword = await bcrypt.compare(password, adminUser.password);
    }
    
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: adminUser._id, username: adminUser.username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.cookie('adminJwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000
    });
    
    res.json({
      success: true,
      token,
      admin: {
        id: adminUser._id,
        username: adminUser.username,
        password: adminUser.password
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
  }
});

// Faculty Routes
app.get('/faculty', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'facultylogin.html'));
});

app.get('/facultyhome', authenticateFaculty, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'facultydashboard.html'));
});

app.get('/faculty/dashboard', authenticateFaculty, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Faculty dashboard accessed successfully', 
    faculty: req.faculty 
  });
});

app.get('/register', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/faculty/register', authenticateToken, async (req, res) => {
  try {
    const { username, password, section, subject } = req.body;
    
    if (!username || !password || !section || !subject) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    const existingFaculty = await Faculty.findOne({ username, section, subject });
    
    if (existingFaculty) {
      return res.status(400).json({ success: false, message: 'Faculty with these credentials already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newFaculty = new Faculty({
      username,
      password: hashedPassword,
      section,
      subject,
    });
    
    await newFaculty.save();
    res.status(201).json({ success: true, message: 'Faculty registered successfully' });
  } catch (err) {
    console.error('Faculty registration error:', err);
    res.status(500).json({ success: false, message: 'Registration failed', error: err.message });
  }
});

app.post('/faculty/login', async (req, res) => {
  try {
    const { username, password, section, subject  } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    
    const faculty = await Faculty.findOne({ username,section });
    
    if (!faculty) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, faculty.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: faculty._id, username: faculty.username, role: 'faculty' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.cookie('facultyJwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000
    });
    
    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      faculty: {
        id: faculty._id,
        name: faculty.name,
        section: faculty.section,
        subject: faculty.subject
      }
    });
  } catch (err) {
    console.error('Faculty login error:', err);
    res.status(500).json({ success: false, message: 'Login failed', error: err.message });
  }
});
app.post('/faculty/feedback-data', authenticateFaculty, async (req, res) => {
  try {
    const facultyId = req.body.facultyId;
    
    // Find documents that contain entries with the matching faculty_id
    const feedbackData = await FacultyFeedback.find({
      "entries.faculty_id": facultyId
    });
    
    let facultyEntries = [];
    
    feedbackData.forEach(doc => {
      // Filter entries array for the specific faculty
      const matchingEntries = doc.entries.filter(entry => 
        entry.faculty_id === facultyId
      );
      
      // Add matching entries to our results
      if (matchingEntries && matchingEntries.length > 0) {
        facultyEntries = facultyEntries.concat(matchingEntries);
      }
    });
    
    console.log(`Found ${facultyEntries.length} feedback entries for faculty ${facultyId}`);
    
    // Find faculty information separately by querying Faculty collection
    // Assuming there's a Faculty model/collection
    const faculty = await Faculty.findById(facultyId);
    
    // Use faculty data from database or construct from entries if available
    const facultyInfo = faculty ? {
      name: faculty.name,
      subject: faculty.subject,
      section: faculty.section
    } : facultyEntries.length > 0 ? {
      // Look through all entries to find one with the faculty info
      name: facultyEntries.find(entry => entry.name)?.name || '',
      subject: facultyEntries.find(entry => entry.subject)?.subject || '',
      section: facultyEntries.find(entry => entry.section)?.section || ''
    } : {};
    
    res.status(200).json({
      success: true,
      faculty: facultyInfo,
      feedbackData: facultyEntries
    });
  } catch (error) {
    console.error('Error fetching feedback data:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch feedback data',
      error: error.message
    });
  }
});
// Student and Feedback Routes
app.get('/student', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedbackhome.html'));
});

app.get('/feedbackform', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedbackform.html'));
});

app.post('/schedule/feedback', authenticateToken, async (req, res) => {
  try {
    const data = req.body;
    
    if (!data.section) {
      return res.status(400).json({ success: false, message: 'Section is required' });
    }
    
    await Schedule.deleteOne({ section: data.section });
    const newSchedule = new Schedule(data);
    await newSchedule.save();
    
    res.status(200).json({ success: true, id: newSchedule._id });
  } catch (err) {
    console.error('Schedule feedback error:', err);
    res.status(500).json({ success: false, message: 'Failed to save feedback', error: err.message });
  }
});

app.post('/validate/passkey', async (req, res) => {
  try {
    const { passkey } = req.body;
    
    if (!passkey) {
      return res.status(400).json({ success: false, message: 'Passkey is required' });
    }
    
    let schedule;
    try {
      const numericPasskey = ObjectId.createFromHexString(passkey);
      schedule = await Schedule.findOne({ _id: numericPasskey });
    } catch (err) {
      return res.status(400).json({ success: false, message: 'Invalid passkey format' });
    }
    
    if (!schedule) {
      return res.status(404).json({ success: false, message: 'Invalid passkey' });
    }
    
    const facultyData = await Faculty.find({ section: schedule.section });
    
    const token = jwt.sign(
      { section: schedule.section, type: 'feedback' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.cookie('feedback_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000
    });
    
    return res.status(200).json({ 
      success: true,
      message: 'Valid passkey',
      facultyData: facultyData.map(f => ({
        id: f._id,
        username: f.username,
        subject: f.subject,
        section: f.section
      })),
      section: schedule.section
    });
  } catch (error) {
    console.error('Passkey validation error:', error);
    return res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

app.post('/feedback', async (req, res) => {
  try {
    console.log("Received feedback data:", JSON.stringify(req.body, null, 2));

    const feedbackArray = req.body.feedback;
    const feedbackId = req.body.feedbackId;

    // Validate input
    if (!Array.isArray(feedbackArray) || feedbackArray.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid feedback data: feedback array is required"
      });
    }

    if (!feedbackId) {
      return res.status(400).json({
        success: false,
        message: "Invalid feedback data: feedbackId is required"
      });
    }

    // Find or create feedback document
    let facultyFeedback;
    try {
      facultyFeedback = await FacultyFeedback.findOne({ feedback_id: feedbackId });
      console.log("Found existing feedback:", facultyFeedback ? "Yes" : "No");
    } catch (dbError) {
      console.error("Database query error:", dbError);
      return res.status(500).json({
        success: false,
        message: "Database query error",
        error: dbError.message
      });
    }

    if (!facultyFeedback) {
      console.log("Creating new feedback document with ID:", feedbackId);
      facultyFeedback = new FacultyFeedback({
        feedback_id: feedbackId,
        entries: []
      });
    }

    console.log("Processing", feedbackArray.length, "feedback entries");

    for (const feedback of feedbackArray) {
      console.log("Processing feedback for:", feedback.name);

      if (!feedback.facultyId) {
        console.warn(`Skipping feedback for ${feedback.name} - Missing facultyId`);
        continue;
      }

      const existingEntryIndex = facultyFeedback.entries.findIndex(
        entry => entry.faculty_id && entry.faculty_id.toString() === feedback.facultyId.toString()
      );

      if (existingEntryIndex !== -1) {
        // Update existing entry
        const existingEntry = facultyFeedback.entries[existingEntryIndex];
        const currentCount = existingEntry.students_count || 1;
        const newCount = currentCount + 1;

        existingEntry.teach = (existingEntry.teach * currentCount + feedback.teach) / newCount;
        existingEntry.depth = (existingEntry.depth * currentCount + feedback.depth) / newCount;
        existingEntry.resource = (existingEntry.resource * currentCount + feedback.resource) / newCount;
        existingEntry.assignment = (existingEntry.assignment * currentCount + feedback.assignment) / newCount;

        if (feedback.comments) {
          existingEntry.comments = existingEntry.comments 
            ? `${existingEntry.comments}\n${feedback.comments}` 
            : feedback.comments;
        }

        existingEntry.students_count = newCount;
      } else {
        // Add new entry
        const newEntry = {
          faculty_id: feedback.facultyId,
          name: feedback.name,
          subject: feedback.subject,
          teach: feedback.teach,
          depth: feedback.depth,
          resource: feedback.resource,
          assignment: feedback.assignment,
          comments: feedback.comments || '',
          students_count: 1
        };

        console.log("Created entry:", newEntry);
        facultyFeedback.entries.push(newEntry);
      }
    }

    // Save the document
    console.log("Saving feedback document...");
    try {
      await facultyFeedback.save();
      console.log("Feedback saved successfully");
    } catch (saveError) {
      console.error("Database save error:", saveError);
      return res.status(500).json({
        success: false,
        message: "Failed to save to database",
        error: saveError.message
      });
    }

    res.status(200).json({
      success: true,
      message: "Thank you for your feedback!",
      count: feedbackArray.length
    });

  } catch (err) {
    console.error('Unhandled error in feedback route:', err);
    res.status(500).json({
      success: false,
      message: "Failed to save feedback",
      error: err.message
    });
  }
});

// app.get('/api/faculty-data', (req, res) => {
//   const token = req.cookies.feedback_session;
  
//   if (!token) {
//     return res.status(401).json({ success: false, message: 'No session found. Please validate your passkey first.' });
//   }
  
//   try {
//     const decoded = jwt.verify(token, JWT_SECRET);
    
//     if (decoded.type !== 'feedback') {
//       return res.status(403).json({ success: false, message: 'Invalid session type' });
//     }
    
//     return res.json({ success: true, section: decoded.section });
//   } catch (error) {
//     console.error('Faculty data retrieval error:', error);
//     return res.status(403).json({ success: false, message: 'Invalid or expired session' });
//   }
// });

// Authentication check and logout routes
app.get('/check/login', (req, res) => {
  const adminToken = req.cookies.adminJwt;
 
  
  // Check for any valid token
  if (!adminToken && !facultyToken && !userToken) {
    return res.status(404).json({ loggedIn: false });
  }
  
  try {
    // Try to verify admin token first
    if (adminToken) {
      const decoded = jwt.verify(adminToken, JWT_SECRET);
      return res.json({
        loggedIn: true,
        user: {
          id: decoded.id,
          username: decoded.username,
          role: decoded.role
        }
      });
    }
    
    // If no admin token, try faculty token
    
    // If no token worked but we got here, return not logged in
    return res.json({ loggedIn: false });
    
  } catch (error) {
    console.error('JWT verification error:', error.message);
    
    // Clear the specific cookie that failed verification
    if (adminToken) res.clearCookie('adminJwt', { path: '/admin' });
    
    return res.json({ loggedIn: false });
  }
});

app.post('/logout', (req, res) => {
  try {
    res.clearCookie('adminJwt', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });
    
    res.clearCookie('feedback_session');
    
    return res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error during logout', 
      error: error.message 
    });
  }
});
app.post('/faculty/logout', (req, res) => {
  try {
    res.clearCookie('facultyJwt', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });
    
    
    return res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Error during logout', 
      error: error.message 
    });
  }
});

// Home route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});