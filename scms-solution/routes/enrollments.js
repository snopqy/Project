const express = require('express');
const router = express.Router();
const supabase = require('../config/supabase');

// POST enroll student
router.post('/', async (req, res) => {
    const { student_id, course_id } = req.body;

    // Check if already enrolled
    const { data: existing } = await supabase
        .from('enrollments')
        .select('*')
        .eq('student_id', student_id)
        .eq('course_id', course_id)
        .single();

    if (existing) {
        return res.status(400).json({ error: 'Student already enrolled in this course' });
    }

    const { data, error } = await supabase
        .from('enrollments')
        .insert([{ student_id, course_id }])
        .select();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json(data[0]);
});

// GET courses for a specific student
router.get('/student/:studentId', async (req, res) => {
    const { studentId } = req.params;

    // Join enrollments with courses
    const { data, error } = await supabase
        .from('enrollments')
        .select(`
            id,
            enrollment_date,
            courses (
                id,
                name,
                description,
                credit
            )
        `)
        .eq('student_id', studentId);

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

module.exports = router;
