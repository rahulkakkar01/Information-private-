const express = require("express");
const path = require("path");
const mongoose = require('mongoose');
const hbs = require("hbs");
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const app = express();

const templatePath = path.join(__dirname, "templates");
const publicPath = path.join(__dirname, "public");
const uploadPath = path.join(__dirname, "uploads");

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "hbs");
app.set("views", templatePath);
app.use(express.static(publicPath)); // Serve static files
app.use('/uploads', express.static(uploadPath)); // Serve uploaded files

// Connect to MongoDB using Mongoose
mongoose.connect('mongodb://localhost:27017/mydb', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to database');
  })
  .catch((error) => {
    console.error('Error connecting to database', error);
    process.exit(1); // Exit the application if the connection fails
  });

// Define User schema and model
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  fileAccessPassword: String,
  resetToken: String,
  resetTokenExpiration: Date
});

const User = mongoose.model('User', userSchema);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// Encryption and Decryption functions
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encrypt(buffer) {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString('hex'), content: encrypted.toString('hex') };
}

function decrypt(encrypted) {
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(encrypted.iv, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted.content, 'hex')), decipher.final()]);
  return decrypted;
}

// Generate a random 4-digit number
function generateRandom4DigitNumber() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// Routes
app.get("/", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.send('User already exists');
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const fileAccessPassword = generateRandom4DigitNumber();
            const newUser = new User({ name, email, password: hashedPassword, fileAccessPassword });
            await newUser.save();
            res.send(`Signup successful. Your file access password is ${fileAccessPassword}. Please <a href="/">login</a>.`);
        }
    } catch (err) {
        console.error('Error during signup', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            res.redirect("/home");
        } else {
            res.send('Invalid email or password. Please <a href="/">try again</a>.');
        }
    } catch (err) {
        console.error('Error during login', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get("/home", (req, res) => {
    res.render("home");
});

app.get("/import", (req, res) => {
    res.render("import");
});

app.post("/import", upload.single('file'), (req, res) => {
    const filePath = path.join(uploadPath, req.file.filename);
    const fileBuffer = fs.readFileSync(filePath);
    const encrypted = encrypt(fileBuffer);
    fs.writeFileSync(filePath, JSON.stringify(encrypted));
    res.send('File uploaded and encrypted successfully. <a href="/home">Go back to home</a>');
});

app.get("/files", (req, res) => {
    res.render("files-password");
});

app.post("/files", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && password === user.fileAccessPassword) {
        fs.readdir(uploadPath, (err, files) => {
            if (err) {
                console.error('Error reading files', err);
                res.status(500).send('Internal Server Error');
                return;
            }
            res.render("files", { files });
        });
    } else {
        res.send('Invalid email or password. Please <a href="/files">try again</a>.');
    }
});

app.get("/download/:filename", (req, res) => {
    const filePath = path.join(uploadPath, req.params.filename);
    const encrypted = JSON.parse(fs.readFileSync(filePath));
    const decrypted = decrypt(encrypted);
    res.setHeader('Content-Disposition', 'attachment; filename=' + req.params.filename);
    res.send(decrypted);
});

// Forgot Password Routes
app.get("/forgot-password", (req, res) => {
    res.render("forgot-password");
});

app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            res.send('No account with that email found.');
            return;
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // 1 hour
        await user.save();

        // Send email with reset link (skipped for simplicity)
        // const resetLink = `http://localhost:3001/reset-password/${token}`;
        // sendEmail(user.email, resetLink);

        res.send('Password reset link has been sent to your email.');
    } catch (err) {
        console.error('Error during forgot password', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get("/reset-password/:token", async (req, res) => {
    try {
        const token = req.params.token;
        const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) {
            res.send('Password reset token is invalid or has expired.');
            return;
        }
        res.render("reset-password", { userId: user._id.toString(), token });
    } catch (err) {
        console.error('Error during reset password', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/reset-password", async (req, res) => {
    try {
        const { userId, token, password } = req.body;
        const user = await User.findOne({ _id: userId, resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) {
            res.send('Password reset token is invalid or has expired.');
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.send('Password has been reset successfully. Please <a href="/">login</a>.');
    } catch (err) {
        console.error('Error during reset password', err);
        res.status(500).send('Internal Server Error');
    }
});

const port = process.env.PORT || 3001;
// const ip = '127.0.0.1';
const ip = '10.11.242.183';

app.listen(port, ip, () => {
    console.log(`Server is running on http://${ip}:${port}`);
});