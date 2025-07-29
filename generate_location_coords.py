import csv
import time
from geopy.geocoders import Nominatim
import mysql.connector

# Database connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="08f_lala",
    database="acci_track",
    ssl_disabled=True
)
cursor = db.cursor()

# Geolocator
geolocator = Nominatim(user_agent="accitrack_locator")

def get_coordinates(location_name):
    try:
        location = geolocator.geocode(f"{location_name}, Baguio City, Philippines")
        if location:
            return round(location.latitude, 6), round(location.longitude, 6)
    except Exception as e:
        print(f"Geocoding failed for {location_name}: {e}")
    return None, None

# Step 1: Read unique barangays from Combined.csv
barangays = set()
with open(r"C:\Users\keith\Downloads\ACCITRACK_csv\Combined.csv", newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        location = row["Barangay/Location"].strip()
        if location:
            barangays.add(location)

# Step 2: Get and insert coordinates
for barangay in sorted(barangays):
    lat, lon = get_coordinates(barangay)
    if lat and lon:
        print(f"Inserting: {barangay} => {lat}, {lon}")
        cursor.execute("""
            INSERT IGNORE INTO locations (location_name, latitude, longitude)
            VALUES (%s, %s, %s)
        """, (barangay, lat, lon))
        db.commit()
    else:
        print(f"Skipping: {barangay} (No coordinates found)")
    time.sleep(1)  # Respect Nominatim rate limits

cursor.close()
db.close()
