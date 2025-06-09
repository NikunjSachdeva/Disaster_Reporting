from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
# from transformers import pipeline
import pyrebase
import random
import smtplib
import os
import geocoder 
from werkzeug.utils import secure_filename
import json
from flask_sqlalchemy import SQLAlchemy
from firebase_admin import credentials, firestore, initialize_app
import logging
from functools import wraps
from datetime import datetime
from flask import session
import webbrowser
from threading import Timer
from transformers import AutoTokenizer, AutoModelForCausalLM
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error
# Firebase configuration

firebase_config = json.loads(os.getenv("FIREBASE_CONFIG"))
firebase = pyrebase.initialize_app(firebase_config)
db = firebase.database()
storage = firebase.storage()  
app = Flask(__name__)
app.secret_key = 'secret_key'  



# Firestore collection references
DISASTERS_COLLECTION = 'disasters'
USERS_COLLECTION = 'users'
# File upload settings
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
UPLOAD_FOLDER = 'uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)







# Global variable to store OTP
otp_cache = {}


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        # Generate OTP
        otp = random.randint(100000, 999999)
        otp_cache[email] = otp

        # Send OTP via email
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(EMAIL, EMAIL_PASSWORD)
                message = f"Subject: OTP Verification\n\nYour OTP for registration is: {otp}"
                server.sendmail(EMAIL, email, message)
            flash('OTP sent to your email.', 'success')
            return render_template('otp_verify.html', email=email, name=name, password=password)
        except Exception as e:
            flash(f"Failed to send OTP. Error: {e}", 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form['email']
    name = request.form['name']
    password = request.form['password']
    entered_otp = request.form['otp']

    # Check OTP
    if email in otp_cache and int(entered_otp) == otp_cache[email]:
        db.child("users").child(email.replace('.', ',')).set({"name": name, "password": password})
        otp_cache.pop(email)  # Remove OTP after use
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid OTP. Please try again.', 'danger')
        return render_template('otp_verify.html', email=email, name=name, password=password)


@app.route('/login', methods=['GET','POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    # Retrieve user from Firebase
    user = db.child("users").child(email.replace('.', ',')).get().val()

    if user and user['password'] == password:
        # Set session for logged-in user
        session['user'] = user['name']
        flash(f"Welcome, {user['name']}!", 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid email or password.', 'danger')
        return redirect(url_for('home'))
    
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    # Admin login
    if request.method == 'POST':
        # Authenticate admin credentials
        email = request.form['email']
        password = request.form['password']
        if email == "nikunj.sachdeva12@gmail.com" and password == "admin123":  # Example credentials
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Admin Credentials!', 'danger')
    return render_template('admin_login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('home'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')




# @app.route('/report_disaster', methods=['GET', 'POST'])
# def report_disaster():
#     if request.method == 'POST':
#         disaster_type = request.form['disaster_type']
#         description = request.form['description']
#         location = request.form['location']

#         # Handle file upload
#         media_file = request.files['media']
#         media_url = None

#         if media_file:
#             # Secure the file name and save it
#             filename = secure_filename(media_file.filename)
#             media_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

#             # Upload to Firebase storage
#             media_url = storage.child(f"disasters/{filename}").put(os.path.join(app.config['UPLOAD_FOLDER'], filename))['downloadUrl']

#         # Save the disaster report to Firebase
#         disaster_data = {
#             'disaster_type': disaster_type,
#             'description': description,
#             'location': location,
#             'media_url': media_url
#         }
#         db.child("disasters").push(disaster_data)

#         flash('Disaster report submitted successfully!', 'success')
#         return redirect(url_for('dashboard'))

#     # Get the current location using geocoder
#     g = geocoder.ip('me')
#     current_location = g.latlng if g.latlng else []

#     return render_template('report_disaster.html', location=current_location)


# @app.route('/report_disaster', methods=['GET', 'POST'])
# def report_disaster():
#     if request.method == 'POST':
#         disaster_type = request.form['disaster_type']
#         description = request.form['description']
#         location = request.form['location']

#         # Handle file upload
#         media_file = request.files['media']
#         media_url = None

#         if media_file:
#             # Secure the file name and save it locally
#             filename = secure_filename(media_file.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             media_file.save(file_path)

#             # Upload to Firebase storage
#             media_url = storage.child(f"disasters/{filename}").put(file_path)['downloadUrl']

#         # Save the disaster report to Firebase
#         disaster_data = {
#             'disaster_type': disaster_type,
#             'description': description,
#             'location': location,
#             'media_url': media_url
#         }
#         db.child("disasters").push(disaster_data)

#         flash('Disaster report submitted successfully!', 'success')
#         return redirect(url_for('dashboard'))

#     # Get the current location using geocoder
#     g = geocoder.ip('me')
#     current_location = g.latlng if g.latlng else []

#     return render_template('report_disaster.html', location=current_location)


@app.route('/report_disaster', methods=['GET', 'POST'])
def report_disaster():
    if request.method == 'POST':
        disaster_type = request.form['disaster_type']
        description = request.form['description']
        location = request.form['location']  

        # Handle file upload
        media_file = request.files['media']
        media_url = None

        if media_file:
            # Secure the file name and save it locally
            filename = secure_filename(media_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            media_file.save(file_path)

            # Upload to Firebase storage
            media_url = storage.child(f"disasters/{filename}").put(file_path)['downloadUrl']

        # Capture the current timestamp when the disaster report is submitted
        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')  # Format the timestamp to ISO 8601 format

        # Save the disaster report to Firebase, including the timestamp
        disaster_data = {
            'disaster_type': disaster_type,
            'description': description,
            'location': location,
            'media_url': media_url,
            'timestamp': timestamp  # Add timestamp to the data
        }
        db.child("disasters").push(disaster_data)

        flash('Disaster report submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('report_disaster.html')


@app.route('/view_reports')
def view_reports():
    if 'user' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('home'))

    # Get all disaster reports from Firebase
    disaster_reports = db.child("disasters").get().val()

    # Check if the report data exists and print it for debugging
    if disaster_reports:
        print("Disaster reports retrieved from Firebase:", disaster_reports)
    else:
        print("No disaster reports found.")

    # Pass the disaster reports to the template
    return render_template('view_reports.html', reports=disaster_reports)





@app.route('/api/disaster-data', methods=['GET'])
def get_disaster_data():
    try:
        # Fetch all disaster reports from Firebase Realtime Database using Pyrebase
        disasters = db.child('disasters').get().val() or {}
        print("Fetched disasters from Firebase:", disasters)  # Debugging: Print the raw data from Firebase
        
        disaster_data = []
        
        # Iterate through all disaster entries
        for key, value in disasters.items():
            print(f"Processing disaster with key {key}: {value}")  # Debugging: Log each disaster entry
            
            # Extract location
            location = value.get('location')
            if location:
                try:
                    # Split location into latitude and longitude
                    print(f"Parsing location: {location}")  # Debugging: Log the location being processed
                    
                    # Check if the location can be split into exactly two values
                    location_parts = location.split(',')
                    if len(location_parts) != 2:
                        print(f"Invalid location format (not two values): {location}")
                        continue
                    
                    # List comprehension
                    latitude = float(location_parts[0].strip())  # Convert latitude to float
                    longitude = float(location_parts[1].strip())  # Convert longitude to float
                    
                    disaster_data.append([latitude, longitude])
                except ValueError as e:
                    print(f"Invalid location format for {location}: {e}")  # Debugging: Log error if the format is wrong
            else:
                print(f"No location found for disaster with key {key}")  # Debugging: Log if no location is present
            
        # Check if disaster_data is empty
        if not disaster_data:
            print("No valid disaster data found.")
        else:
            print("Success")
        # Continue with returning the data in the response
        return jsonify(disaster_data), 200
    
    except Exception as e:
        print(f"Error occurred: {str(e)}")  # Debugging: Log the exception message
        return jsonify({'error': str(e)}), 500




@app.route('/api/disasters', methods=['GET'])
def get_disaster_overview():
    try:
        # Fetch all disaster reports from Firebase Realtime Database
        disasters = db.child(DISASTERS_COLLECTION).get()

        if not disasters.each():
            return jsonify([]), 200  # Return an empty array if no data exists

        disaster_list = []
        total_reports = 0  # Initialize total_reports
        disaster_types = {}
        pending_reports = 0
        

        # Iterate through disaster records
        for disaster in disasters.each():
            data = disaster.val()
            data['id'] = disaster.key()  # Add the unique ID for the disaster

            # Increment total reports
            total_reports += 1

            # Extract or infer disaster type
            disaster_type = data.get('disaster_type', 'Unknown')
            disaster_types[disaster_type] = disaster_types.get(disaster_type, 0) + 1

            # Handle status field: default to "pending" if not present
            status = data.get('status', 'pending')
            if status == 'pending':
                pending_reports += 1

            # Update the database with default "pending" status if not already set
            if 'status' not in data:
                db.child(DISASTERS_COLLECTION).child(disaster.key()).update({'status': 'pending'})
            
            disaster_list.append(data)

        # Prepare the response with disaster list and additional stats
        response = {
            'total_reports': total_reports,  # Include total_reports in the response
            'disaster_types': disaster_types,
            'pending_reports': pending_reports,
            'disasters': disaster_list  # Include the detailed disaster reports
           
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/report/verify/<report_id>', methods=['POST'])
def verify_report(report_id):
    report_path = f"disasters/{report_id}"  # Ensure correct path
    report = db.child(report_path).get()

    if not report.val():
        return jsonify({"error": f"Report with ID {report_id} does not exist"}), 404

    # Check if the 'flag' field exists, if not, add it
    current_data = report.val()
    if "flag" not in current_data:
        db.child(report_path).update({"flag": "verified"})  # Add the flag if it doesn't exist
    else:
        # If flag exists, update it
        db.child(report_path).update({"flag": "verified"})

    # Add or update the 'comment' field
    db.child(report_path).update({"comment": "Verified by admin"})

    return jsonify({"message": f"Report {report_id} successfully verified."})



# @app.route('/api/report/reject/<report_id>', methods=['POST'])
# def reject_report(report_id):
#     report_path = f"disasters/{report_id}"  # Ensure correct path
#     report = db.child(report_path).get()

#     if not report.val():
#         return jsonify({"error": f"Report with ID {report_id} does not exist"}), 404

#     # Check if the 'flag' field exists, if not, add it
#     current_data = report.val()
#     if "flag" not in current_data:
#         db.child(report_path).update({"flag": "rejected"})  # Add the flag if it doesn't exist
#     else:
#         # If flag exists, update it
#         db.child(report_path).update({"flag": "rejected"})

#     # Add or update the 'comment' field
#     db.child(report_path).update({"comment": "Inappropriate content"})

#     return jsonify({"message": f"Report {report_id} successfully rejected."})




@app.route('/api/report/reject/<report_id>', methods=['POST'])
def reject_report(report_id):
    # Ensure the request contains JSON
    if not request.is_json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    # Retrieve confirmation from the request body
    confirmation = request.json.get('confirmation', False)

    # Proceed with the rest of the rejection logic
    report_path = f"disasters/{report_id}"
    report = db.child(report_path).get()

    if not report.val():
        return jsonify({"error": f"Report with ID {report_id} does not exist"}), 404

    # Check if the 'flag' field exists, if not, add it
    current_data = report.val()
    if "flag" not in current_data:
        db.child(report_path).update({"flag": "rejected"})
    else:
        db.child(report_path).update({"flag": "rejected"})

    db.child(report_path).update({"comment": "Inappropriate content"})

    if confirmation:
        # If confirmed, delete the report
        db.child(report_path).remove()
        return jsonify({"message": f"Report {report_id} has been rejected and deleted."})

    return jsonify({"message": f"Report {report_id} has been rejected. Awaiting confirmation for deletion."})




# Route to delete reports based on certain conditions
@app.route('/api/report/delete/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    report = Report.query.get(report_id)
    
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # For inappropriate content, run through some filter (e.g., AI)
    if is_inappropriate(report.description):
        db.session.delete(report)
        db.session.commit()
        return jsonify({'message': 'Inappropriate report deleted.'}), 200
    
    # Duplicate report check (simple check based on location and disaster type)
    duplicate_report = Report.query.filter_by(
        location=report.location, disaster_type=report.disaster_type).first()
    
    if duplicate_report and duplicate_report.id != report.id:
        db.session.delete(report)
        db.session.commit()
        return jsonify({'message': 'Duplicate report deleted.'}), 200
    
    return jsonify({'error': 'No action needed for this report.'}), 200





@app.route('/api/report/<report_id>/status', methods=['PUT'])
def update_report_status(report_id):
    data = request.get_json()
    new_status = data.get('status')
    print(f"Updating report {report_id} to status: {new_status}")  # Debug log

        
    if new_status == 'in-progress':
        db.child('disasters').child(report_id).update({"status": "in-progress"})
    if new_status == 'completed':
        db.child('disasters').child(report_id).update({"status": "completed"})
        
    # Reference to the report in Firebase by ID
    report_ref = db.child('disasters').child(report_id)

    # Check if the report exists
    report = report_ref.get()
    if not report.val():
        return jsonify({'error': 'Report not found'}), 404

    # Update the status of the report
    
    updated_report = report_ref.get()
    print(f"Updated Report: {updated_report.val()}")  # Debug log to check if the update is reflected

    return jsonify({'message': 'Status updated successfully'})

    
    
    
    
    
def send_email(recipient_email, subject, message):
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL, EMAIL_PASSWORD)
            email_message = f"Subject: {subject}\n\n{message}"
            server.sendmail(EMAIL, recipient_email, email_message)
            print(f"Notification sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def format_email(email):
    # Replace commas with dots in email address
    return email.replace(',', '.')

@app.route('/admin/notifications', methods=['GET', 'POST'])
def notifications():
    if request.method == 'POST':
        notification_type = request.form['notification_type']
        message = request.form['message']
        title = request.form['title']

        # Mass notification logic (send to all users)
        if notification_type == 'mass':
            users = db.child("users").get()  # Get all users
            for user in users.each():
                email = user.key()  # The email is the key in the user data
                formatted_email = format_email(email)  # Format the email
                if formatted_email:
                    send_email(formatted_email, title, message)
                else:
                    print(f"Email not found for user: {user.val()}")

        # Targeted notification logic (send to specific user)
        elif notification_type == 'targeted':
            email = request.form['email']
            formatted_email = format_email(email)  # Format the email
            send_email(formatted_email, title, message)

        flash('Notification sent successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('notification.html')

    


@app.route('/admin/analytics', methods=['GET'])
def analytics():
    # Fetch disaster data from Firebase
    disasters = db.child('disasters').get()  # Assuming 'disasters' node stores disaster reports

    # Prepare data for analytics
    disaster_dates = {}
    affected_regions = {}

    for disaster in disasters.each():
        disaster_data = disaster.val()
        
        # 'Timestamp' is the field storing date and time of the disaster
        timestamp = disaster_data.get('timestamp', None)  # Using .get to avoid KeyError if not found
        
        if timestamp:
            # Convert timestamp to date object (assuming it's in ISO 8601 format)
            date_obj = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')  # Adjust if needed
            date_key = date_obj.strftime('%Y-%m-%d')  # Format as date (e.g., 2024-11-23)
            
            # Group by date for trends over time
            if date_key not in disaster_dates:
                disaster_dates[date_key] = 0
            disaster_dates[date_key] += 1

        # Group by region for most affected regions
        region = disaster_data.get('region', 'Unknown Region')  # Default to 'Unknown Region' if missing
        if region not in affected_regions:
            affected_regions[region] = 0
        affected_regions[region] += 1

    # Prepare data for charting (convert dict to list of tuples)
    date_labels = list(disaster_dates.keys())
    date_values = list(disaster_dates.values())
    
    region_labels = list(affected_regions.keys())
    region_values = list(affected_regions.values())

    return render_template('analytics.html', 
                           date_labels=date_labels, 
                           date_values=date_values,
                           region_labels=region_labels,
                           region_values=region_values)



# llm = CTransformers(model='models',
#                     model_type='llama',
#                     config={'max_new_tokens': 256, 'temperature': 0.01})




import logging
import requests

logger = logging.getLogger(__name__)


def getgeminiresponse(input_text: str, blog_style: str = 'Disaster Guide') -> str:
    """
    Generate disaster-related guidance using the Gemini API with a styled prompt.
    
    Args:
        input_text: The disaster-related query or topic (e.g., 'What to do during an earthquake?').
        blog_style: The style of the response (default: 'Disaster Guide').
    
    Returns:
        str: The generated disaster guidance or an error message.
    """
    # Define the prompt template
    template = """
    Act as a disaster guide and provide clear, actionable advice in the style of a {blog_style} for the query "{input_text}".
    Ensure the response is concise, empathetic, and includes practical steps or safety tips.
    """
    
    # Format the prompt with the provided inputs
    prompt = template.format(blog_style=blog_style, input_text=input_text)
    
    # Prepare the API request
    headers = {'Content-Type': 'application/json'}
    data = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.01,
            "maxOutputTokens": 256
        }
    }
    
    try:
        # Make the API call
        response = requests.post(GEMINI_URL, headers=headers, json=data)
        if response.status_code == 200:
            response_data = response.json()
            # Extract text from the first candidate's content
            candidates = response_data.get('candidates', [])
            if candidates and 'content' in candidates[0] and 'parts' in candidates[0]['content']:
                return candidates[0]['content']['parts'][0].get('text', 'No guidance generated.')
            return 'No guidance generated.'
        return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        logger.error(f"Error in Gemini API call: {str(e)}")
        return "An error occurred while generating disaster guidance."    

# def get_llama_response(input_text, blog_style='Common People'):
#     # Define the prompt template
#     template = """
#     Write a response in the style of a {blog_style} for the topic "{input_text}".
#     """
    
#     # Format the prompt with the provided inputs
#     prompt = template.format(blog_style=blog_style, input_text=input_text)
    
#     # Generate the response from the LLaMA model
#     response = llm(prompt)
#     return response



@app.route('/chat', methods=['POST'])
def handle_message():
    user_message = request.json.get('message')
    
    response = getgeminiresponse(user_message)
    return jsonify({'reply': response})
    

@app.route('/chatbot')
def chatbot_page():
    return render_template('chatbot.html')


@app.route('/map')
def map():
    return render_template('map.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))





def open_browser():
    # Open the browser at the specified URL
    webbrowser.open_new("https://127.0.0.1:5000/")

if __name__ == "__main__":
    # Check if this is the main process or the reloader subprocess
    # if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    #     Timer(1, open_browser).start()

    # # Start the Flask app
    # app.run(debug=True, host="127.0.0.1", port=5000 , ssl_context=('localhost.pem', 'localhost-key.pem'))
    app.run(debug=True)


# if __name__ == '__main__':
#     # app.run(host = '192.168.1.56', port = '5000', debug=True, ssl_context=('localhost.pem', 'localhost-key.pem'))
#     app.run(debug=True, ssl_context=('localhost.pem', 'localhost-key.pem'))

