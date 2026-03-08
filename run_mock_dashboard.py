import sqlite3
import random
from datetime import datetime, timedelta

def generate_mock_data():
    db_path = r"c:\Users\ADMIN\Desktop\Project\fitness.sqlite"
    
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        
        # Get active residents
        cur.execute("SELECT id FROM residents WHERE active = 1 AND deleted_at IS NULL")
        resident_ids = [row[0] for row in cur.fetchall()]
        
        if not resident_ids:
            print("No active residents found.")
            return

        print(f"Found {len(resident_ids)} active residents.")
        
        # Generate data for the last 7 days (including today)
        total_inserted = 0
        for i in range(7):
            d = datetime.now() - timedelta(days=i)
            # Random number of check-ins per day (e.g. 15 to 50)
            num_checkins = random.randint(15, 50)
            
            for _ in range(num_checkins):
                rid = random.choice(resident_ids)
                # Random time during the day (6 AM to 10 PM)
                hour = random.randint(6, 22)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                
                checkin_time = d.replace(hour=hour, minute=minute, second=second)
                checkin_str = checkin_time.strftime("%Y-%m-%d %H:%M:%S")
                
                cur.execute("INSERT INTO checkins (resident_id, checkin_time) VALUES (?, ?)", (rid, checkin_str))
                total_inserted += 1
                
        conn.commit()
        print(f"Successfully generated {total_inserted} mock check-in records for the last 7 days.")

if __name__ == "__main__":
    generate_mock_data()
