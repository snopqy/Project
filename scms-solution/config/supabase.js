const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('Error: SUPABASE_URL and SUPABASE_KEY are required in .env');
    // We don't exit here to allow the server to start even if config is missing, 
    // but API calls will fail.
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;
