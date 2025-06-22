// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/peace-community', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// Email configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    country: { type: String, trim: true },
    password: { type: String, required: true, minlength: 6 },
    role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
    interests: [{ type: String }],
    isActive: { type: Boolean, default: true },
    joinedDate: { type: Date, default: Date.now },
    lastLogin: { type: Date },
    profilePicture: { type: String },
    bio: { type: String, maxlength: 500 }
});

const User = mongoose.model('User', userSchema);

// Contact Form Schema
const contactSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true },
    country: { type: String, trim: true },
    interest: { type: String, required: true },
    message: { type: String, required: true, maxlength: 1000 },
    status: { type: String, enum: ['new', 'in-progress', 'resolved'], default: 'new' },
    submittedAt: { type: Date, default: Date.now },
    responseNote: { type: String }
});

const Contact = mongoose.model('Contact', contactSchema);

// Program Schema
const programSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date },
    location: { type: String },
    isVirtual: { type: Boolean, default: false },
    maxParticipants: { type: Number },
    currentParticipants: { type: Number, default: 0 },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['upcoming', 'ongoing', 'completed', 'cancelled'], default: 'upcoming' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Program = mongoose.model('Program', programSchema);

// News/Blog Schema
const newsSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    summary: { type: String, required: true, maxlength: 200 },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    category: { type: String, required: true },
    tags: [{ type: String }],
    featuredImage: { type: String },
    isPublished: { type: Boolean, default: false },
    publishedAt: { type: Date },
    views: { type: Number, default: 0 },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const News = mongoose.model('News', newsSchema);

// Donation Schema
const donationSchema = new mongoose.Schema({
    donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: { type: Number, required: true, min: 1 },
    currency: { type: String, default: 'USD' },
    donorName: { type: String },
    donorEmail: { type: String },
    isAnonymous: { type: Boolean, default: false },
    paymentMethod: { type: String, required: true },
    transactionId: { type: String, unique: true },
    status: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending' },
    purpose: { type: String },
    createdAt: { type: Date, default: Date.now }
});

const Donation = mongoose.model('Donation', donationSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Validation Middleware
const validateContactForm = (req, res, next) => {
    const { name, email, interest, message } = req.body;
    
    if (!name || !email || !interest || !message) {
        return res.status(400).json({ message: 'All required fields must be filled' });
    }
    
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }
    
    if (message.length > 1000) {
        return res.status(400).json({ message: 'Message too long (max 1000 characters)' });
    }
    
    next();
};

// ROUTES

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Peace Community API is running',
        timestamp: new Date().toISOString()
    });
});

// Contact Form Submission
app.post('/api/contact', validateContactForm, async (req, res) => {
    try {
        const { name, email, country, interest, message } = req.body;
        
        const contact = new Contact({
            name,
            email,
            country,
            interest,
            message
        });
        
        await contact.save();
        
        // Send confirmation email to user
        const userEmailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Thank you for contacting International Peace Community',
            html: `
                <h2>Thank you for reaching out, ${name}!</h2>
                <p>We have received your message and will get back to you within 24-48 hours.</p>
                <p><strong>Your message:</strong></p>
                <p>${message}</p>
                <br>
                <p>Best regards,<br>International Peace Community Team</p>
            `
        };
        
        // Send notification email to admin
        const adminEmailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL,
            subject: 'New Contact Form Submission',
            html: `
                <h2>New Contact Form Submission</h2>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Country:</strong> ${country || 'Not specified'}</p>
                <p><strong>Interest:</strong> ${interest}</p>
                <p><strong>Message:</strong></p>
                <p>${message}</p>
                <p><strong>Submitted at:</strong> ${new Date().toLocaleString()}</p>
            `
        };
        
        await Promise.all([
            transporter.sendMail(userEmailOptions),
            transporter.sendMail(adminEmailOptions)
        ]);
        
        res.status(201).json({ 
            message: 'Thank you for your message! We will contact you soon.',
            submissionId: contact._id
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ message: 'Failed to submit contact form' });
    }
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, country, interests } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email, and password are required' });
        }
        
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const user = new User({
            name,
            email,
            password: hashedPassword,
            country,
            interests: interests || []
        });
        
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                country: user.country,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        if (!user.isActive) {
            return res.status(403).json({ message: 'Account is deactivated' });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                country: user.country,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

// Get User Profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch profile' });
    }
});

// Get Programs
app.get('/api/programs', async (req, res) => {
    try {
        const { category, status, page = 1, limit = 10 } = req.query;
        const filter = {};
        
        if (category) filter.category = category;
        if (status) filter.status = status;
        
        const programs = await Program.find(filter)
            .populate('organizer', 'name email')
            .sort({ startDate: 1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await Program.countDocuments(filter);
        
        res.json({
            programs,
            pagination: {
                current: page,
                pages: Math.ceil(total / limit),
                total
            }
        });
    } catch (error) {
        console.error('Programs fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch programs' });
    }
});

// Create Program (Admin/Moderator only)
app.post('/api/programs', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'user') {
            return res.status(403).json({ message: 'Only admins and moderators can create programs' });
        }
        
        const programData = {
            ...req.body,
            organizer: req.user.userId
        };
        
        const program = new Program(programData);
        await program.save();
        
        const populatedProgram = await Program.findById(program._id)
            .populate('organizer', 'name email');
        
        res.status(201).json({
            message: 'Program created successfully',
            program: populatedProgram
        });
    } catch (error) {
        console.error('Program creation error:', error);
        res.status(500).json({ message: 'Failed to create program' });
    }
});

// Join Program
app.post('/api/programs/:id/join', authenticateToken, async (req, res) => {
    try {
        const program = await Program.findById(req.params.id);
        if (!program) {
            return res.status(404).json({ message: 'Program not found' });
        }
        
        if (program.participants.includes(req.user.userId)) {
            return res.status(400).json({ message: 'Already joined this program' });
        }
        
        if (program.maxParticipants && program.currentParticipants >= program.maxParticipants) {
            return res.status(400).json({ message: 'Program is full' });
        }
        
        program.participants.push(req.user.userId);
        program.currentParticipants += 1;
        await program.save();
        
        res.json({ message: 'Successfully joined the program' });
    } catch (error) {
        console.error('Program join error:', error);
        res.status(500).json({ message: 'Failed to join program' });
    }
});

// Get News/Blog Posts
app.get('/api/news', async (req, res) => {
    try {
        const { category, page = 1, limit = 10 } = req.query;
        const filter = { isPublished: true };
        
        if (category) filter.category = category;
        
        const news = await News.find(filter)
            .populate('author', 'name')
            .sort({ publishedAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await News.countDocuments(filter);
        
        res.json({
            news,
            pagination: {
                current: page,
                pages: Math.ceil(total / limit),
                total
            }
        });
    } catch (error) {
        console.error('News fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch news' });
    }
});

// Create News Post (Admin/Moderator only)
app.post('/api/news', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'user') {
            return res.status(403).json({ message: 'Only admins and moderators can create news posts' });
        }
        
        const newsData = {
            ...req.body,
            author: req.user.userId,
            publishedAt: req.body.isPublished ? new Date() : null
        };
        
        const news = new News(newsData);
        await news.save();
        
        const populatedNews = await News.findById(news._id)
            .populate('author', 'name');
        
        res.status(201).json({
            message: 'News post created successfully',
            news: populatedNews
        });
    } catch (error) {
        console.error('News creation error:', error);
        res.status(500).json({ message: 'Failed to create news post' });
    }
});

// Process Donation
app.post('/api/donations', async (req, res) => {
    try {
        const { amount, donorName, donorEmail, isAnonymous, purpose, paymentMethod } = req.body;
        
        if (!amount || amount <= 0) {
            return res.status(400).json({ message: 'Valid donation amount is required' });
        }
        
        const donation = new Donation({
            donor: req.user?.userId,
            amount,
            donorName,
            donorEmail,
            isAnonymous: isAnonymous || false,
            purpose,
            paymentMethod,
            transactionId: `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        });
        
        await donation.save();
        
        // Here you would integrate with payment processor (Stripe, PayPal, etc.)
        // For now, we'll simulate successful payment
        donation.status = 'completed';
        await donation.save();
        
        res.status(201).json({
            message: 'Donation processed successfully',
            transactionId: donation.transactionId,
            amount: donation.amount
        });
    } catch (error) {
        console.error('Donation error:', error);
        res.status(500).json({ message: 'Failed to process donation' });
    }
});

// Admin: Get Dashboard Stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [
            totalUsers,
            totalPrograms,
            totalDonations,
            recentContacts,
            totalDonationAmount
        ] = await Promise.all([
            User.countDocuments({ isActive: true }),
            Program.countDocuments(),
            Donation.countDocuments({ status: 'completed' }),
            Contact.countDocuments({ status: 'new' }),
            Donation.aggregate([
                { $match: { status: 'completed' } },
                { $group: { _id: null, total: { $sum: '$amount' } } }
            ])
        ]);
        
        res.json({
            totalUsers,
            totalPrograms,
            totalDonations,
            recentContacts,
            totalDonationAmount: totalDonationAmount[0]?.total || 0
        });
    } catch (error) {
        console.error('Stats fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
    }
});

// Admin: Get All Contacts
app.get('/api/admin/contacts', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        const filter = {};
        
        if (status) filter.status = status;
        
        const contacts = await Contact.find(filter)
            .sort({ submittedAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await Contact.countDocuments(filter);
        
        res.json({
            contacts,
            pagination: {
                current: page,
                pages: Math.ceil(total / limit),
                total
            }
        });
    } catch (error) {
        console.error('Contacts fetch error:', error);
        res.status(500).json({ message: 'Failed to fetch contacts' });
    }
});

// Admin: Update Contact Status
app.patch('/api/admin/contacts/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status, responseNote } = req.body;
        
        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { status, responseNote },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({ message: 'Contact not found' });
        }
        
        res.json({ message: 'Contact updated successfully', contact });
    } catch (error) {
        console.error('Contact update error:', error);
        res.status(500).json({ message: 'Failed to update contact' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Peace Community Server is running on port ${PORT}`);
    console.log(`📍 API Base URL: http://localhost:${PORT}/api`);
});

module.exports = app;