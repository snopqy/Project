const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Supabase Setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
let supabase;

if (supabaseUrl && supabaseKey) {
    supabase = createClient(supabaseUrl, supabaseKey);
    console.log('Supabase connected');
} else {
    console.warn('WARNING: SUPABASE_URL or SUPABASE_KEY missing. Database calls will fail.');
}

// --- Routes ---

// Students
app.get('/api/students', async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not configured' });
    const { data, error } = await supabase.from('students').select('*');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/students', async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not configured' });
    const { fullname, email, major } = req.body;
    const { data, error } = await supabase.from('students').insert([{ fullname, email, major }]).select();
    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

// Courses
app.get('/api/courses', async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not configured' });
    const { data, error } = await supabase.from('courses').select('*');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/courses', async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not configured' });
    const { name, description, credit } = req.body;
    const { data, error } = await supabase.from('courses').insert([{ name, description, credit }]).select();
    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

// Enrollments
app.post('/api/enrollments', async (req, res) => {
    if (!supabase) return res.status(500).json({ error: 'Database not configured' });
    const { student_id, course_id } = req.body;
    const { data, error } = await supabase.from('enrollments').insert([{ student_id, course_id }]).select();
    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.get('/', (req, res) => res.send('SCMS API (Demo Mode) is running!'));

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
