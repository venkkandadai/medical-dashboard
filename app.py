import streamlit as st
import pandas as pd
import altair as alt
import datetime
import os
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import time
import json
import uuid

# Load data
@st.cache_data
def load_data():
    students = pd.read_csv("students (1).csv")
    exam_records = pd.read_csv("exam_records.csv")
    epc_scores = pd.read_csv("epc_scores.csv")
    qlf_responses = pd.read_csv("qlf_responses.csv")
    return students, exam_records, epc_scores, qlf_responses

# --- ADMIN CONFIGURATION ---
# 🔄 IMPORTANT: Add your email address to access analytics
ADMIN_EMAILS = [
    "venkkandadai@gmail.com",  # 🔄 Replace with YOUR email address
    "medschool.dashboard.prototype@gmail.com",  # System email has admin access
    # Add more researcher/admin emails as needed:
    # "researcher2@university.edu",
    # "supervisor@medschool.edu", 
]

def is_admin(user_email):
    """Check if user has admin access to analytics"""
    return user_email in ADMIN_EMAILS
def initialize_session():
    """Initialize session tracking"""
    if "session_id" not in st.session_state:
        st.session_state["session_id"] = str(uuid.uuid4())
        st.session_state["session_start"] = time.time()
        # Log session start
        current_user = st.session_state.get("username")
        if current_user:
            log_user_action(current_user, "session_start", {
                "session_id": st.session_state["session_id"],
                "start_time": st.session_state["session_start"]
            })

def log_session_activity():
    """Log ongoing session activity (called on each page load)"""
    current_user = st.session_state.get("username")
    if current_user and "session_start" in st.session_state:
        current_time = time.time()
        session_duration = current_time - st.session_state["session_start"]
        
        log_user_action(current_user, "session_activity", {
            "session_id": st.session_state["session_id"],
            "session_duration_seconds": round(session_duration, 1),
            "session_duration_minutes": round(session_duration / 60, 2)
        })

def log_user_action(user_email, action, details=None):
    """Log user actions for experiment analytics"""
    if user_email:  # Only log for authenticated users
        
        # Convert pandas/numpy types to native Python types for JSON serialization
        def make_json_serializable(obj):
            """Convert pandas/numpy types to JSON-serializable types"""
            if hasattr(obj, 'item'):  # numpy types
                return obj.item()
            elif hasattr(obj, 'to_pydatetime'):  # pandas datetime
                return obj.to_pydatetime().isoformat()
            elif isinstance(obj, dict):
                return {k: make_json_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [make_json_serializable(item) for item in obj]
            else:
                return obj
        
        # Clean the details dictionary
        clean_details = make_json_serializable(details or {})
        
        log_entry = {
            "timestamp": time.time(),
            "datetime": datetime.datetime.now().isoformat(),
            "session_id": st.session_state.get("session_id", "unknown"),
            "user_email": user_email,
            "action": action,
            "details": clean_details,
            "page_mode": st.session_state.get("current_mode", "unknown")
        }
        
        # Save to analytics file
        analytics_file = "experiment_analytics.json"
        with open(analytics_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

def log_page_view(user_email, mode):
    """Track page/mode changes"""
    st.session_state["current_mode"] = mode
    log_user_action(user_email, "page_view", {"mode": mode})

def log_student_lookup(user_email, student_id, student_name, exam_filter):
    """Track student lookup behavior"""
    log_user_action(user_email, "student_lookup", {
        "student_id": student_id,
        "student_name": student_name,
        "exam_filter": exam_filter
    })

def log_cohort_analysis(user_email, cohort_year, exam_filter):
    """Track cohort analysis behavior"""
    log_user_action(user_email, "cohort_analysis", {
        "cohort_year": cohort_year,
        "exam_filter": exam_filter
    })

def log_feature_interaction(user_email, feature, details):
    """Track specific feature usage"""
    log_user_action(user_email, "feature_interaction", {
        "feature": feature,
        "details": details
    })

# Initialize session tracking
initialize_session()

# Log session activity (for duration tracking)
if st.session_state.get("username"):
    log_session_activity()

# --- EMAIL CONFIGURATION ---
# ⚠️ IMPORTANT: Configure these settings for your email provider
# For Gmail: Use an "App Password" instead of your regular password
# Enable 2FA first, then generate app password at: https://myaccount.google.com/apppasswords
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",  
    "smtp_port": 587,                 
    "sender_email": "medschool.dashboard.prototype@gmail.com",        # ✅ Your account
    "sender_password": "bmhv xocb zsgd moic",                         # ✅ Your app password
    "sender_name": "Wharton Street College of Medicine Dashboard RUs"
}

def send_reset_email(recipient_email, reset_token, recipient_name):
    """Send password reset email with secure token"""
    try:
        # Create reset link - update this URL when you deploy
        base_url = "http://localhost:8501"  # 🔄 Change this to your deployed URL
        reset_link = f"{base_url}/?reset_token={reset_token}"
        
        # Create email content
        subject = "Password Reset Request - Wharton Street College of Medicine Dashboard"
        
        html_body = f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>Hello {recipient_name},</p>
                <p>You requested a password reset for your Wharton Street College Dashboard account.</p>
                <p><strong>Click the link below to reset your password:</strong></p>
                <p><a href="{reset_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>Or copy and paste this link into your browser:</p>
                <p>{reset_link}</p>
                <p><strong>This link will expire in 1 hour for security.</strong></p>
                <p>If you didn't request this reset, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Wharton Street College IT Support</p>
            </body>
        </html>
        """
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{EMAIL_CONFIG['sender_name']} <{EMAIL_CONFIG['sender_email']}>"
        msg['To'] = recipient_email
        
        # Add HTML content
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.send_message(msg)
        
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

def generate_reset_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def save_reset_token(email, token):
    """Save reset token with timestamp"""
    token_file = "reset_tokens.csv"
    current_time = time.time()
    
    # Load existing tokens or create new DataFrame
    if os.path.exists(token_file):
        tokens_df = pd.read_csv(token_file)
    else:
        tokens_df = pd.DataFrame(columns=["email", "token", "timestamp"])
    
    # Remove old tokens for this email
    tokens_df = tokens_df[tokens_df["email"] != email]
    
    # Add new token
    new_token = pd.DataFrame([{
        "email": email,
        "token": token,
        "timestamp": current_time
    }])
    tokens_df = pd.concat([tokens_df, new_token], ignore_index=True)
    
    # Clean up expired tokens (older than 1 hour)
    one_hour_ago = current_time - 3600
    tokens_df = tokens_df[tokens_df["timestamp"] > one_hour_ago]
    
    # Save updated tokens
    tokens_df.to_csv(token_file, index=False)

def verify_reset_token(token):
    """Verify if reset token is valid and not expired"""
    token_file = "reset_tokens.csv"
    
    if not os.path.exists(token_file):
        return None
    
    tokens_df = pd.read_csv(token_file)
    current_time = time.time()
    one_hour_ago = current_time - 3600
    
    # Find valid token
    valid_token = tokens_df[
        (tokens_df["token"] == token) & 
        (tokens_df["timestamp"] > one_hour_ago)
    ]
    
    if not valid_token.empty:
        return valid_token.iloc[0]["email"]
    return None

def clear_reset_token(token):
    """Remove used reset token"""
    token_file = "reset_tokens.csv"
    
    if os.path.exists(token_file):
        tokens_df = pd.read_csv(token_file)
        tokens_df = tokens_df[tokens_df["token"] != token]
        tokens_df.to_csv(token_file, index=False)

# --- AUTHENTICATION SETUP ---
user_db_path = "users.csv"

# Force login or registration
if "authentication_status" not in st.session_state or not st.session_state["authentication_status"]:
    st.sidebar.title("Wharton Street College of Medicine Dashboard")
    auth_mode = st.sidebar.radio("Account Access", ["Login", "Register", "Reset Password"])
    st.session_state["auth_mode"] = auth_mode
else:
    auth_mode = st.session_state.get("auth_mode", "Login")

if auth_mode == "Register":
    st.sidebar.header("Create a New Account")
    new_email = st.sidebar.text_input("Email")
    new_first_name = st.sidebar.text_input("First Name")
    new_last_name = st.sidebar.text_input("Last Name")
    new_title = st.sidebar.text_input("Title")
    new_medical_school = st.sidebar.text_input("Medical School Name")
    new_password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Register"):
        if os.path.exists(user_db_path):
            users_df = pd.read_csv(user_db_path)
        else:
            users_df = pd.DataFrame(columns=["email", "first_name", "last_name", "name", "title", "medical_school", "password"])

        if new_email in users_df["email"].values:
            st.sidebar.error("Email already registered.")
        else:
            hashed_pw = stauth.Hasher([new_password]).generate()[0]
            # Create full name for compatibility with authenticator
            full_name = f"{new_first_name} {new_last_name}".strip()
            users_df = pd.concat([
                users_df,
                pd.DataFrame([{
                    "email": new_email, 
                    "first_name": new_first_name,
                    "last_name": new_last_name,
                    "name": full_name,  # Keep for authenticator compatibility
                    "title": new_title,
                    "medical_school": new_medical_school,
                    "password": hashed_pw
                }])
            ], ignore_index=True)
            users_df.to_csv(user_db_path, index=False)
            st.sidebar.success("Account created. Please return to Login.")
        st.stop()

# Login section info
if auth_mode == "Login":
    st.sidebar.info("💡 **Forgot your password?** Use the 'Reset Password' option above to receive a secure reset link via email.")

# Check for reset token in URL parameters
query_params = st.query_params
reset_token = query_params.get("reset_token", None)

if reset_token:
    # Handle password reset with token
    st.sidebar.header("🔒 Reset Your Password")
    
    # Verify token
    token_email = verify_reset_token(reset_token)
    if token_email:
        st.sidebar.success("✅ Valid reset link!")
        new_password = st.sidebar.text_input("Enter New Password", type="password", key="new_pwd")
        confirm_password = st.sidebar.text_input("Confirm New Password", type="password", key="confirm_pwd")
        
        if st.sidebar.button("Update Password"):
            if new_password and new_password == confirm_password:
                if len(new_password) >= 6:
                    # Load users and update password
                    if os.path.exists(user_db_path):
                        users_df = pd.read_csv(user_db_path)
                        hashed_pw = stauth.Hasher([new_password]).generate()[0]
                        users_df.loc[users_df["email"] == token_email, "password"] = hashed_pw
                        users_df.to_csv(user_db_path, index=False)
                        
                        # Clear the used token
                        clear_reset_token(reset_token)
                        
                        st.sidebar.success("✅ Password updated successfully!")
                        st.sidebar.info("Please log in with your new password.")
                        
                        # Clear URL parameters
                        st.query_params.clear()
                        st.rerun()
                    else:
                        st.sidebar.error("User database not found.")
                else:
                    st.sidebar.error("Password must be at least 6 characters long.")
            else:
                st.sidebar.error("Passwords don't match or are empty.")
    else:
        st.sidebar.error("❌ Invalid or expired reset link.")
        st.sidebar.info("Please request a new password reset.")
    
    st.stop()

if auth_mode == "Reset Password":
    st.sidebar.header("🔑 Request Password Reset")
    st.sidebar.info("Enter your email address and we'll send you a secure reset link.")
    
    reset_email = st.sidebar.text_input("Email Address")
    
    if st.sidebar.button("Send Reset Email"):
        if reset_email:
            # Check if email exists
            if os.path.exists(user_db_path):
                users_df = pd.read_csv(user_db_path)
                if reset_email in users_df["email"].values:
                    # Generate and save token
                    token = generate_reset_token()
                    save_reset_token(reset_email, token)
                    
                    # Get user name for personalized email
                    user_info = users_df[users_df["email"] == reset_email].iloc[0]
                    user_name = user_info.get("name", user_info.get("first_name", "User"))
                    
                    # Send email (only if EMAIL_CONFIG is properly configured)
                    if EMAIL_CONFIG["sender_email"] != "your-email@gmail.com":
                        if send_reset_email(reset_email, token, user_name):
                            st.sidebar.success("✅ Reset email sent! Check your inbox.")
                            st.sidebar.info("The reset link will expire in 1 hour.")
                        else:
                            st.sidebar.error("❌ Failed to send email. Contact administrator.")
                    else:
                        st.sidebar.warning("⚠️ Email not configured. Contact administrator.")
                        st.sidebar.info(f"Admin: Use token {token} for manual reset.")
                else:
                    # Don't reveal if email exists or not (security)
                    st.sidebar.success("✅ If that email exists, a reset link has been sent.")
            else:
                st.sidebar.error("User database not found.")
        else:
            st.sidebar.error("Please enter an email address.")
    st.stop()

# Login logic
if os.path.exists(user_db_path):
    users_df = pd.read_csv(user_db_path)
    
    # Handle legacy user databases that might not have new columns
    if "first_name" not in users_df.columns:
        users_df["first_name"] = ""
    if "last_name" not in users_df.columns:
        users_df["last_name"] = ""
    if "title" not in users_df.columns:
        users_df["title"] = ""
    if "medical_school" not in users_df.columns:
        users_df["medical_school"] = ""
    
    # Create full name field if it doesn't exist (for authenticator compatibility)
    if "name" not in users_df.columns:
        users_df["name"] = (users_df["first_name"] + " " + users_df["last_name"]).str.strip()
    
    # For legacy users who only have "name" field, try to split into first/last
    missing_names = users_df["first_name"].fillna("") == ""
    if missing_names.any():
        for idx, row in users_df[missing_names].iterrows():
            if pd.notna(row["name"]) and row["name"].strip():
                name_parts = row["name"].strip().split()
                users_df.loc[idx, "first_name"] = name_parts[0] if name_parts else ""
                users_df.loc[idx, "last_name"] = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
else:
    st.error("No users registered yet. Please register.")
    st.stop()

user_creds = {
    "usernames": {
        row["email"]: {"name": row["name"], "password": row["password"]}
        for _, row in users_df.iterrows()
    }
}

cookie_config = {
    "name": "dashboard_auth",
    "key": "some_secret",
    "expiry_days": 1  # expires after 1 day instead of when browser closes
}

authenticator = stauth.Authenticate(user_creds, cookie_config["name"], cookie_config["key"], cookie_config["expiry_days"])

name, authentication_status, username = authenticator.login("Login", "main")
st.session_state["authentication_status"] = authentication_status
if authentication_status:
    st.session_state["username"] = username
    st.session_state["name"] = name
    # Log successful login
    log_user_action(username, "login_success", {"name": name})

if authentication_status is False:
    st.error("Username or password is incorrect")
elif authentication_status is None:
    st.warning("Please enter your username and password")
    st.stop()

if authentication_status:
    try:
        if authenticator.logout("Logout", "sidebar"):
            # Log session end before clearing
            current_user = st.session_state.get("username")
            if current_user and "session_start" in st.session_state:
                session_end_time = time.time()
                session_duration = session_end_time - st.session_state["session_start"]
                log_user_action(current_user, "session_end", {
                    "session_id": st.session_state["session_id"],
                    "session_duration_seconds": round(session_duration, 1),
                    "session_duration_minutes": round(session_duration / 60, 2)
                })
            
            st.session_state.clear()
            st.rerun()
    except KeyError:
        # Handle case where cookie doesn't exist
        current_user = st.session_state.get("username")
        if current_user and "session_start" in st.session_state:
            session_end_time = time.time()
            session_duration = session_end_time - st.session_state["session_start"]
            log_user_action(current_user, "session_end", {
                "session_id": st.session_state["session_id"],
                "session_duration_seconds": round(session_duration, 1),
                "session_duration_minutes": round(session_duration / 60, 2)
            })
        
        st.session_state.clear()
        st.rerun()

# Welcome screen
st.sidebar.title("Wharton Street College of Medicine Dashboard")

# Show Analytics tab only for admin users
current_user = st.session_state.get("username")
if current_user and is_admin(current_user):
    mode_options = ["Home", "Student Lookup", "Cohort Summary", "📊 Analytics"]
else:
    mode_options = ["Home", "Student Lookup", "Cohort Summary"]

mode = st.sidebar.radio("Select a View:", mode_options)

# Log page navigation
if current_user:
    log_page_view(current_user, mode)

if mode == "Home":
    st.markdown("\n---\n")
    st.write("Welcome! Use the options on the left to begin.")
    
    # Display user profile information
    if authentication_status and username:
        user_info = users_df[users_df["email"] == username].iloc[0]
        st.subheader("Your Profile")
        col1, col2 = st.columns(2)
        
        with col1:
            if user_info.get('first_name') and user_info.get('last_name'):
                st.write(f"**Name:** {user_info['first_name']} {user_info['last_name']}")
            elif user_info.get('name'):
                st.write(f"**Name:** {user_info['name']}")
            st.write(f"**Email:** {user_info['email']}")
        
        with col2:
            if user_info.get('title'):
                st.write(f"**Title:** {user_info['title']}")
            if user_info.get('medical_school'):
                st.write(f"**Medical School:** {user_info['medical_school']}")
        
        # Log profile view
        log_feature_interaction(username, "profile_view", {
            "has_title": bool(user_info.get('title')),
            "has_medical_school": bool(user_info.get('medical_school'))
        })
        
        # Admin quick stats (only for admins)
        if is_admin(username):
            st.markdown("---")
            st.subheader("🔧 Admin Quick Stats")
            
            # Load basic analytics for quick view
            analytics_file = "experiment_analytics.json"
            if os.path.exists(analytics_file):
                try:
                    with open(analytics_file, "r") as f:
                        line_count = sum(1 for _ in f)
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if 'users_df' in locals():
                            user_count = len(users_df)
                            st.metric("👥 Total Users", user_count)
                        else:
                            st.metric("👥 Total Users", "N/A")
                    with col2:
                        st.metric("📊 Total Actions", line_count)
                    with col3:
                        st.info("📈 View full analytics in Analytics tab")
                        
                    # Show data status for admin
                    if st.session_state.get('data_loaded', False):
                        students_data = st.session_state['students']
                        st.success(f"✅ Dashboard data: {len(students_data)} students loaded")
                    else:
                        st.warning("⚠️ Dashboard data not loaded")
                        
                except Exception as e:
                    st.info("📊 Analytics data will appear as users interact with the dashboard")
            else:
                st.info("📊 Analytics data will appear as users interact with the dashboard")

elif mode == "Student Lookup":
    # st.write("🔍 DEBUG: Entering Student Lookup")
    
    # Load data directly here - forget about session state for now
    try:
        # st.write("🔍 DEBUG: Loading students data directly...")
        students = pd.read_csv("students (1).csv")
        exam_records = pd.read_csv("exam_records.csv")
        epc_scores = pd.read_csv("epc_scores.csv")
        qlf_responses = pd.read_csv("qlf_responses.csv")
        # st.success(f"✅ Data loaded: {len(students)} students, {len(exam_records)} exam records")
    except Exception as e:
        st.error(f"❌ Failed to load data: {str(e)}")
        st.stop()
        
    st.sidebar.header("Student Filters")
    students["full_name"] = students["last_name"].str.strip() + ", " + students["first_name"].str.strip()
    students = students.sort_values(["full_name", "student_id"])
    student_name_map = dict(zip(students["full_name"], students["student_id"]))
    student_id_map = dict(zip(students["student_id"], students["full_name"]))
    
    # Use only one primary selector to avoid sync issues
    selected_name = st.sidebar.selectbox("Select Student Name", list(student_name_map.keys()))
    selected_id = student_name_map[selected_name]
    
    # Show the corresponding ID for reference
    st.sidebar.info(f"Student ID: {selected_id}")

    student_exams = exam_records[exam_records["student_id"] == selected_id]
    student_epc = epc_scores[epc_scores["student_id"] == selected_id]
    student_qlf = qlf_responses[qlf_responses["student_id"] == selected_id]

    exam_ids = student_exams[["exam_type", "exam_date"]].drop_duplicates()
    exam_ids["label"] = exam_ids["exam_type"] + " - " + exam_ids["exam_date"]
    exam_ids = exam_ids.sort_values("exam_date")
    exam_label_map = dict(zip(exam_ids["label"], zip(exam_ids["exam_type"], exam_ids["exam_date"])))
    selected_exam_label = st.sidebar.selectbox("Select Exam Type and Date", ["All"] + list(exam_label_map.keys()))

    # Log student lookup with filters
    current_user = st.session_state.get("username")
    if current_user:
        log_student_lookup(current_user, selected_id, selected_name, selected_exam_label)

    if selected_exam_label != "All":
        selected_exam_type, selected_exam_date = exam_label_map[selected_exam_label]
        student_exams = student_exams[(student_exams["exam_type"] == selected_exam_type) & (student_exams["exam_date"] == selected_exam_date)]
        student_epc = student_epc[(student_epc["exam_type"] == selected_exam_type) & (student_epc["exam_date"] == selected_exam_date)]
        student_qlf = student_qlf[(student_qlf["exam_type"] == selected_exam_type) & (student_qlf["exam_date"] == selected_exam_date)]

    st.markdown(f"### **Student:** {selected_name}  **ID:** {selected_id}")
    st.header(f"Student Dashboard: {selected_name}")
    first_name = selected_name.split(",")[1].strip() if "," in selected_name else selected_name.split()[0]
    if st.button(f"View {first_name}'s INSIGHTS®"):
        st.info("Coming soon!")
        # Log INSIGHTS button click
        if current_user:
            log_feature_interaction(current_user, "insights_button_click", {"student_id": selected_id})

    # Exam History
    st.subheader("Exam History")
    def color_flag(val):
        if val == "Green": return "background-color: #d4edda"
        elif val == "Yellow": return "background-color: #fff3cd"
        elif val == "Red": return "background-color: #f8d7da"
        return ""
    styled_exams = student_exams[["exam_type", "exam_date", "total_score", "flag"]].sort_values("exam_date")
    st.dataframe(styled_exams.style.map(color_flag, subset=["flag"]))

    # Score trend over time
    if selected_exam_label == "All" and not student_exams.empty:
        st.subheader("Score Trend Over Time")
        score_trend_chart = alt.Chart(student_exams).mark_circle(size=100).encode(
            x=alt.X("exam_date:T", title="Exam Date"),
            y=alt.Y("total_score:Q", title="Score"),
            color=alt.Color("exam_type:N", title="Exam Type"),
            tooltip=["exam_type", "exam_date", "total_score"]
        ).properties(height=300)
        st.altair_chart(score_trend_chart, use_container_width=True)

    # EPC
    st.subheader("EPC Content Area Scores")
    if not student_epc.empty:
        epc_long = student_epc.melt(id_vars=["student_id", "exam_type", "exam_date"], var_name="EPC", value_name="Score")
        epc_chart = alt.Chart(epc_long).mark_bar().encode(
            x=alt.X("EPC", sort="-y"),
            y="Score",
            color="exam_type",
            column="exam_type"
        ).properties(width=200)
        st.altair_chart(epc_chart, use_container_width=True)
        st.markdown("**Top Areas for Improvement:**")
        weakest_epcs = epc_long.sort_values("Score").head(5)
        for _, row in weakest_epcs.iterrows():
            st.markdown(f"- {row['EPC']}: {row['Score']:.1f}%")
    else:
        st.write("No EPC data available.")

    # QLF
    st.subheader("QLF Content Category Breakdown")
    if not student_qlf.empty:
        qlf_summary = student_qlf.groupby("score_category")["correct"].agg(["count", "sum"])
        qlf_summary["% Correct"] = 100 * qlf_summary["sum"] / qlf_summary["count"]
        qlf_summary = qlf_summary.rename(columns={"count": "Items", "sum": "Correct"})
        st.dataframe(qlf_summary[["Items", "Correct", "% Correct"]].sort_values("% Correct"))
        st.markdown("**Top QLF Areas for Improvement:**")
        weakest_qlf = qlf_summary.sort_values("% Correct").head(5)
        for index, row in weakest_qlf.iterrows():
            st.markdown(f"- {index}: {row['% Correct']:.1f}%")
    else:
        st.write("No QLF data available.")

elif mode == "Cohort Summary":
    # st.write("🔍 DEBUG: Entering Cohort Summary")
    
    # Load data directly here - simple and reliable
    try:
        # st.write("🔍 DEBUG: Loading cohort data directly...")
        students = pd.read_csv("students (1).csv")
        exam_records = pd.read_csv("exam_records.csv")
        epc_scores = pd.read_csv("epc_scores.csv")
        qlf_responses = pd.read_csv("qlf_responses.csv")
        # st.success(f"✅ Data loaded: {len(students)} students, {len(exam_records)} exam records")
    except Exception as e:
        st.error(f"❌ Failed to load data: {str(e)}")
        st.stop()
        
    st.sidebar.header("Cohort Filters")
    cohort_years = sorted(students["cohort_year"].dropna().unique())
    selected_cohort = st.sidebar.selectbox("Select Cohort Year", ["All"] + list(cohort_years))

    cohort_students = students if selected_cohort == "All" else students[students["cohort_year"] == selected_cohort]
    cohort_ids = cohort_students["student_id"]

    cohort_exam_ids = exam_records[exam_records["student_id"].isin(cohort_ids)][["exam_type", "exam_date"]].drop_duplicates()
    cohort_exam_ids = cohort_exam_ids[cohort_exam_ids["exam_type"].notnull() & cohort_exam_ids["exam_date"].notnull()]
    cohort_exam_ids["label"] = cohort_exam_ids["exam_type"] + " - " + cohort_exam_ids["exam_date"]
    cohort_exam_label_map = dict(zip(cohort_exam_ids["label"], zip(cohort_exam_ids["exam_type"], cohort_exam_ids["exam_date"])))
    selected_label = st.sidebar.selectbox("Select Exam Type and Date", ["All"] + list(cohort_exam_label_map.keys()))

    # Log cohort analysis
    current_user = st.session_state.get("username")
    if current_user:
        log_cohort_analysis(current_user, selected_cohort, selected_label)

    if selected_label != "All":
        selected_exam_type, selected_exam_date = cohort_exam_label_map[selected_label]
    else:
        selected_exam_type = selected_exam_date = None

    st.header(f"Cohort Summary: {selected_cohort}")

    # Exam Scores
    st.subheader("Average Exam Scores")
    exams = exam_records[exam_records["student_id"].isin(cohort_ids)]
    if selected_exam_type:
        exams = exams[(exams["exam_type"] == selected_exam_type) & (exams["exam_date"] == selected_exam_date)]
    if not exams.empty:
        score_stats = exams.groupby(["exam_type", "exam_date"]).agg(
            Num_Students=("student_id", "nunique"),
            Min_Score=("total_score", "min"),
            Q1_Score=("total_score", lambda x: x.quantile(0.25)),
            Median_Score=("total_score", "median"),
            Average_Score=("total_score", "mean"),
            Std_Dev_Score=("total_score", "std"),
            Q3_Score=("total_score", lambda x: x.quantile(0.75)),
            Max_Score=("total_score", "max")
        ).reset_index()
        st.dataframe(score_stats)
        bar_chart = alt.Chart(score_stats).mark_bar().encode(
            x=alt.X("exam_type", title="Exam Type"),
            y=alt.Y("Average_Score", type="quantitative"),
            tooltip=["exam_type", "Average_Score"]
        )
        st.altair_chart(bar_chart, use_container_width=True)
    else:
        st.write("No exam data for this selection.")

    # EPC
    st.subheader("Average EPC Scores")
    cohort_epcs = epc_scores[epc_scores["student_id"].isin(cohort_ids)]
    if selected_exam_type:
        cohort_epcs = cohort_epcs[(cohort_epcs["exam_type"] == selected_exam_type) & (cohort_epcs["exam_date"] == selected_exam_date)]
    if not cohort_epcs.empty:
        epc_columns = cohort_epcs.columns.difference(["student_id", "exam_type", "exam_date"])
        epc_means = cohort_epcs[epc_columns].mean().sort_values()
        df = epc_means.reset_index().rename(columns={"index": "EPC", 0: "Average Score"})
        st.dataframe(df)
        epc_chart = alt.Chart(df).mark_bar().encode(
            x=alt.X("EPC", sort="-y"),
            y="Average Score"
        )
        st.altair_chart(epc_chart, use_container_width=True)

        selected_epc = st.selectbox("Select EPC category to drill down", df["EPC"].tolist())
        if selected_epc:
            # Log EPC drill-down
            if current_user:
                log_feature_interaction(current_user, "epc_drilldown", {"category": selected_epc})
            
            st.subheader(f"Student Scores for {selected_epc}")
            detailed_epc = cohort_epcs[["student_id", "exam_type", "exam_date", selected_epc]].merge(
                students[["student_id", "first_name", "last_name"]], on="student_id"
            )
            detailed_epc["first_name"] = detailed_epc["first_name"].str.replace(",", "", regex=False).str.strip()
            detailed_epc["last_name"] = detailed_epc["last_name"].str.replace(",", "", regex=False).str.strip()
            
            detailed_epc = detailed_epc.rename(columns={selected_epc: "Score"})
            st.dataframe(detailed_epc[["student_id", "first_name", "last_name", "exam_type", "exam_date", "Score"]].sort_values("Score"))
    else:
        st.write("No EPC data for this selection.")

    # QLF
    st.subheader("Cohort QLF Performance")
    cohort_qlf = qlf_responses[qlf_responses["student_id"].isin(cohort_ids)]
    if selected_exam_type:
        cohort_qlf = cohort_qlf[(cohort_qlf["exam_type"] == selected_exam_type) & (cohort_qlf["exam_date"] == selected_exam_date)]
    if not cohort_qlf.empty:
        qlf_grouped = cohort_qlf.groupby("score_category")["correct"].agg(["count", "sum"])
        qlf_grouped["% Correct"] = 100 * qlf_grouped["sum"] / qlf_grouped["count"]
        qlf_grouped = qlf_grouped.rename(columns={"count": "Items", "sum": "Correct"})
        st.dataframe(qlf_grouped[["Items", "Correct", "% Correct"]].sort_values("% Correct"))
        st.altair_chart(
            alt.Chart(qlf_grouped.reset_index()).mark_bar().encode(
                x=alt.X("score_category", sort="-y", title="QLF Category"),
                y="% Correct"
            ), use_container_width=True
        )

        selected_qlf = st.selectbox("Select QLF category to drill down", qlf_grouped.reset_index()["score_category"].tolist())
        if selected_qlf:
            # Log QLF drill-down
            if current_user:
                log_feature_interaction(current_user, "qlf_drilldown", {"category": selected_qlf})
            
            st.subheader(f"Student Scores for {selected_qlf}")
            detailed_qlf = cohort_qlf[cohort_qlf["score_category"] == selected_qlf]
            detailed_qlf = detailed_qlf.groupby(["student_id", "exam_type", "exam_date"]).agg(
                Num_Items=("correct", "count"),
                Num_Correct=("correct", "sum")
            ).reset_index()
            detailed_qlf["% Correct"] = 100 * detailed_qlf["Num_Correct"] / detailed_qlf["Num_Items"]
            detailed_qlf = detailed_qlf.merge(students[["student_id", "first_name", "last_name"]], on="student_id")
            detailed_qlf["first_name"] = detailed_qlf["first_name"].str.replace(",", "", regex=False).str.strip()
            detailed_qlf["last_name"] = detailed_qlf["last_name"].str.replace(",", "", regex=False).str.strip()
            st.dataframe(detailed_qlf[["student_id", "first_name", "last_name", "exam_type", "exam_date", "% Correct"]].sort_values("% Correct"))
    else:
        st.write("No QLF data for this selection.")

elif mode == "📊 Analytics":
    # Admin access control
    current_user = st.session_state.get("username")
    if not current_user or not is_admin(current_user):
        st.error("🔒 Access Denied")
        st.warning("Analytics access is restricted to administrators only.")
        st.info("Contact your system administrator if you need access to usage analytics.")
        st.stop()
    
    st.header("📊 Experiment Analytics Dashboard")
    st.markdown("*Track user engagement and behavior patterns during your experiment*")
    
    # Admin indicator
    st.success(f"👨‍💼 Admin Access: {current_user}")
    
    # Load analytics data
    analytics_file = "experiment_analytics.json"
    if os.path.exists(analytics_file):
        try:
            analytics_data = []
            with open(analytics_file, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        # Ensure details field exists
                        if "details" not in entry:
                            entry["details"] = {}
                        analytics_data.append(entry)
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
            
            if analytics_data:
                df_analytics = pd.DataFrame(analytics_data)
                df_analytics["datetime"] = pd.to_datetime(df_analytics["datetime"])
                
                # Ensure details column is properly formatted
                df_analytics["details"] = df_analytics["details"].fillna({}).apply(
                    lambda x: x if isinstance(x, dict) else {}
                )
                
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    unique_users = df_analytics["user_email"].nunique()
                    st.metric("👥 Total Users", unique_users)
                
                with col2:
                    total_sessions = df_analytics["session_id"].nunique()
                    st.metric("🔄 Total Sessions", total_sessions)
                
                with col3:
                    total_actions = len(df_analytics)
                    st.metric("⚡ Total Actions", total_actions)
                
                with col4:
                    if total_actions > 0:
                        avg_actions = round(total_actions / unique_users, 1)
                        st.metric("📊 Actions/User", avg_actions)
                
                # Session analytics
                st.subheader("🕒 Session Analytics")
                
                # Sessions per user
                sessions_per_user = df_analytics.groupby("user_email")["session_id"].nunique().reset_index()
                sessions_per_user.columns = ["User", "Session Count"]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Sessions per User:**")
                    avg_sessions = sessions_per_user["Session Count"].mean()
                    st.metric("📱 Avg Sessions/User", f"{avg_sessions:.1f}")
                    st.dataframe(sessions_per_user.sort_values("Session Count", ascending=False))
                
                with col2:
                    # Session duration analysis
                    session_activities = df_analytics[df_analytics["action"] == "session_activity"]
                    if not session_activities.empty:
                        st.markdown("**Session Durations:**")
                        
                        try:
                            # Get latest duration for each session (most accurate)
                            durations = []
                            
                            for _, row in session_activities.iterrows():
                                details = row.get("details", {})
                                if isinstance(details, dict) and "session_duration_minutes" in details:
                                    duration = details["session_duration_minutes"]
                                    if isinstance(duration, (int, float)) and duration > 0:
                                        durations.append(duration)
                            
                            if durations:
                                avg_duration = sum(durations) / len(durations)
                                st.metric("⏱️ Avg Session (min)", f"{avg_duration:.1f}")
                                
                                # Duration distribution
                                duration_df = pd.DataFrame({"Duration_Minutes": durations})
                                fig_duration = alt.Chart(duration_df).mark_bar().encode(
                                    x=alt.X("Duration_Minutes:Q", bin=True, title="Duration (minutes)"),
                                    y=alt.Y("count():Q", title="Number of Sessions"),
                                    tooltip=["count()"]
                                ).properties(title="Session Duration Distribution", width=300)
                                st.altair_chart(fig_duration, use_container_width=True)
                            else:
                                st.info("Session duration data will appear as users continue using the dashboard.")
                        except Exception as e:
                            st.warning(f"Session duration analysis temporarily unavailable: {str(e)}")
                            st.info("This will resolve as more session data is collected.")
                    else:
                        st.info("Session duration tracking will appear as users navigate the dashboard.")
                
                # User engagement patterns
                st.subheader("👥 User Engagement Patterns")
                
                # Return user analysis
                user_session_counts = sessions_per_user["Session Count"]
                new_users = (user_session_counts == 1).sum()
                returning_users = (user_session_counts > 1).sum()
                
                engagement_col1, engagement_col2, engagement_col3 = st.columns(3)
                
                with engagement_col1:
                    st.metric("🆕 New Users", new_users)
                
                with engagement_col2:
                    st.metric("🔄 Returning Users", returning_users)
                
                with engagement_col3:
                    if unique_users > 0:
                        return_rate = (returning_users / unique_users) * 100
                        st.metric("📈 Return Rate", f"{return_rate:.1f}%")
                
                # Feature usage breakdown
                st.subheader("🎯 Feature Usage")
                try:
                    page_usage = df_analytics[df_analytics["action"] == "page_view"]["details"].apply(
                        lambda x: x.get("mode", "unknown") if isinstance(x, dict) else "unknown"
                    ).value_counts()
                    
                    if not page_usage.empty:
                        # Create properly named DataFrame for Altair
                        page_usage_df = page_usage.reset_index()
                        page_usage_df.columns = ["Dashboard_Section", "Page_Views"]
                        
                        fig_pages = alt.Chart(page_usage_df).mark_bar().encode(
                            x=alt.X("Dashboard_Section:N", title="Dashboard Section"),
                            y=alt.Y("Page_Views:Q", title="Page Views"),
                            color=alt.Color("Dashboard_Section:N", legend=None),
                            tooltip=["Dashboard_Section", "Page_Views"]
                        ).properties(title="Dashboard Section Usage", width=400)
                        st.altair_chart(fig_pages, use_container_width=True)
                    else:
                        st.info("Feature usage data will appear as users navigate the dashboard.")
                except Exception as e:
                    st.warning(f"Feature usage analysis temporarily unavailable: {str(e)}")
                    st.info("This will resolve as users navigate between dashboard sections.")
                
                # User activity timeline
                st.subheader("📅 User Activity Timeline")
                try:
                    daily_activity = df_analytics.groupby(df_analytics["datetime"].dt.date).size().reset_index()
                    daily_activity.columns = ["Date", "Actions"]
                    
                    if not daily_activity.empty:
                        fig_timeline = alt.Chart(daily_activity).mark_line(point=True).encode(
                            x=alt.X("Date:T", title="Date"),
                            y=alt.Y("Actions:Q", title="Actions"),
                            tooltip=["Date", "Actions"]
                        ).properties(title="Daily Activity", width=500)
                        st.altair_chart(fig_timeline, use_container_width=True)
                    else:
                        st.info("Activity timeline will show patterns as usage grows.")
                except Exception as e:
                    st.warning(f"Timeline analysis temporarily unavailable: {str(e)}")
                    st.info("Timeline will appear as more daily activity is recorded.")
                
                # Most analyzed students (synthetic data)
                st.subheader("🔍 Most Analyzed Students")
                try:
                    student_lookups = df_analytics[df_analytics["action"] == "student_lookup"]
                    if not student_lookups.empty:
                        student_names = []
                        for _, row in student_lookups.iterrows():
                            details = row.get("details", {})
                            if isinstance(details, dict):
                                student_name = details.get("student_name", "unknown")
                                if student_name and student_name != "unknown":
                                    student_names.append(student_name)
                        
                        if student_names:
                            student_analysis = pd.Series(student_names).value_counts().head(10)
                            student_df = student_analysis.reset_index()
                            student_df.columns = ["Student Name", "Times Analyzed"]
                            st.dataframe(student_df)
                        else:
                            st.info("Student analysis data will appear as users examine individual students.")
                    else:
                        st.info("Student analysis tracking will show which synthetic students get the most attention.")
                except Exception as e:
                    st.warning(f"Student analysis temporarily unavailable: {str(e)}")
                    st.info("This will resolve as users start looking up individual students.")
                
                # Feature interactions
                st.subheader("⚙️ Feature Interactions")
                try:
                    feature_interactions = df_analytics[df_analytics["action"] == "feature_interaction"]
                    if not feature_interactions.empty:
                        feature_names = []
                        for _, row in feature_interactions.iterrows():
                            details = row.get("details", {})
                            if isinstance(details, dict):
                                feature_name = details.get("feature", "unknown")
                                if feature_name and feature_name != "unknown":
                                    feature_names.append(feature_name)
                        
                        if feature_names:
                            feature_usage = pd.Series(feature_names).value_counts()
                            feature_df = feature_usage.reset_index()
                            feature_df.columns = ["Feature", "Usage Count"]
                            st.dataframe(feature_df)
                            
                            # Show INSIGHTS® clicks specifically
                            insights_clicks = feature_df[feature_df["Feature"] == "insights_button_click"]
                            if not insights_clicks.empty:
                                insights_count = insights_clicks["Usage Count"].iloc[0]
                                st.metric("🔍 INSIGHTS® Button Clicks", insights_count)
                        else:
                            st.info("Feature interaction data will appear as users engage with different features.")
                    else:
                        st.info("Feature interaction tracking will show INSIGHTS® clicks, drill-downs, and other interactions.")
                except Exception as e:
                    st.warning(f"Feature interaction analysis temporarily unavailable: {str(e)}")
                    st.info("This will resolve as users interact with features like INSIGHTS® and drill-downs.")
                
                # Raw data option
                if st.checkbox("Show Raw Analytics Data"):
                    st.subheader("📋 Raw Analytics Log")
                    st.dataframe(df_analytics.sort_values("datetime", ascending=False))
                
            else:
                st.info("No analytics data collected yet. Start using the dashboard to see analytics!")
        
        except Exception as e:
            st.error(f"Error loading analytics data: {str(e)}")
            st.info("This may be due to malformed data. Try clearing the analytics file or contact support.")
            
            # Show raw file contents for debugging
            if st.checkbox("Show raw analytics file for debugging"):
                try:
                    with open(analytics_file, "r") as f:
                        raw_content = f.read()
                    st.text_area("Raw analytics file content:", raw_content, height=200)
                except Exception as read_error:
                    st.error(f"Could not read analytics file: {str(read_error)}")
    else:
        st.info("📈 Analytics will appear here once users start interacting with the dashboard!")
        st.markdown("""
        **What gets tracked:**
        - Page navigation patterns
        - Student lookup behavior  
        - Cohort analysis usage
        - Feature interactions (INSIGHTS®, drill-downs)
        - Session duration and frequency
        - Most analyzed students and data types
        """)
        
    # Download analytics data
    if os.path.exists(analytics_file):
        with open(analytics_file, "r") as f:
            analytics_content = f.read()
        
        st.download_button(
            label="📥 Download Analytics Data",
            data=analytics_content,
            file_name=f"experiment_analytics_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )