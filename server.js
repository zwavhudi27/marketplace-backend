const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('API is running...');
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'Please provide all fields' });

  try {
    const existingUser = await db('users').where('email', email).first();
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const [id] = await db('users').insert({
      username,
      email,
      password: hashedPassword
    });

    const token = jwt.sign({ id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });

    res.json({ message: 'User registered', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Please provide email and password' });

  try {
    const user = await db('users').where('email', email).first();
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to verify JWT token for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, no token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'secretkey', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Add product endpoint (protected)
app.post('/products', authenticateToken, async (req, res) => {
  const { name, price, description } = req.body;

  if (!name || !price)
    return res.status(400).json({ error: 'Name and price are required' });

  try {
    const [id] = await db('products').insert({
      name,
      price,
      description,
      user_id: req.user.id
    });
    res.json({ message: 'Product added', id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// Public products listing
app.get('/products', async (req, res) => {
  try {
    const products = await db('products').select('*');
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
