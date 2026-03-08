const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');

// GET all students
router.get('/', async (req, res) => {
    const { data, error } = await supabase.from('students').select('*');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// GET student by ID
router.get('/:id', async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('students').select('*').eq('id', id).single();
    if (error) return res.status(404).json({ error: 'Student not found' });
    res.json(data);
});

// POST create student
router.post('/', async (req, res) => {
    const { fullname, email, major } = req.body;
    const { data, error } = await supabase
        .from('students')
        .insert([{ fullname, email, major }])
        .select();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

// PUT update student
router.put('/:id', async (req, res) => {
    const { id } = req.params;
    const { fullname, email, major } = req.body;
    const { data, error } = await supabase
        .from('students')
        .update({ fullname, email, major })
        .eq('id', id)
        .select();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data[0]);
});

// DELETE student
router.delete('/:id', async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('students').delete().eq('id', id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Student deleted successfully' });
});

module.exports = router;
