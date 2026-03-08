const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');

// GET all courses
router.get('/', async (req, res) => {
    const { data, error } = await supabase.from('courses').select('*');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// POST create course
router.post('/', async (req, res) => {
    const { name, description, credit } = req.body;
    const { data, error } = await supabase
        .from('courses')
        .insert([{ name, description, credit }])
        .select();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

module.exports = router;
