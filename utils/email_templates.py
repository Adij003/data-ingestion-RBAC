

def html_description_user(admin: str, user: str, project: dict, manager: str):
    return f"""
    <h2 style="color: #2e86de;">🎉Project Assignment Notification</h2>
    <p> hey {user} 👋</p>
    <p>We’re pleased to inform you that <strong>your project has been approved</strong> by {admin}.</p>

    <h3>📄 Project Summary:</h3>
    <ul>
        <li><strong>Project Name:</strong> {project.project_name}</li>
        <li><strong>Description:</strong> {project.project_description}</li>
        <li><strong>Status:</strong> {project.project_status}</li>
        <li><strong>Start Date:</strong> {project.start_date}</li>
        <li><strong>End Date:</strong> {project.end_date}</li>
    </ul>

    <p><strong>Manager Leading the Project:</strong> {manager}</p>

    <p>Best of luck on your project journey!</p>
    <p style="margin-top: 30px;">Regards,<br>C2DeVal Team</p>
    """

def admin_To_manager_project_Assignment(project: dict, manager: str, admin: str):
    return f"""
    <h2 style="color: #28a745;">✅ Project Assignment</h2>
    <p>Dear {manager},</p>
 
    <p>Good news! Your have been Assigned  a  project   <strong> by {admin}</strong> Details  of the  Project  are as  follows.</p>
 
    <h3>📄 Project Summary:</h3>
    <ul>
        <li><strong>Project Name:</strong> {project.project_name}</li>
        <li><strong>Description:</strong> {project.project_description}</li>
        <li><strong>Status:</strong> {project.project_status}</li>
        <li><strong>Start Date:</strong> {project.start_date}</li>
        <li><strong>End Date:</strong> {project.end_date}</li>
    </ul>
 
    <p>You are now the assigned manager for this project. Kindly initiate the onboarding and planning steps.</p>
 
    <p style="margin-top: 30px;">Regards,<br>C2DeVal Team</p>
    """


def html_description_manager(project: dict, manager: str, admin: str):
    return f"""
    <h2 style="color: #28a745;">✅ Project Approval Confirmation</h2>
    <p>Dear {manager},</p>

    <p>Good news! Your request for the following project has been <strong>approved by {admin}</strong>.</p>

    <h3>📄 Project Summary:</h3>
    <ul>
        <li><strong>Project Name:</strong> {project.project_name}</li>
        <li><strong>Description:</strong> {project.project_description}</li>
        <li><strong>Status:</strong> {project.project_status}</li>
        <li><strong>Start Date:</strong> {project.start_date}</li>
        <li><strong>End Date:</strong> {project.end_date}</li>
    </ul>

    <p>You are now the assigned manager for this project. Kindly initiate the onboarding and planning steps.</p>

    <p style="margin-top: 30px;">Regards,<br>C2DeVal Team</p>
    """

def manager_request_user_assignment_template(admin: str, manager: str, user: str, role: str, users: dict, project: str):
    return f"""
    <h2 style="color: #ffc107;">🔔 Project Assignment Request</h2>
    <p>Dear {admin},</p>

    <p>Manager <strong>{manager}</strong> is requesting approval to assign the project <strong>{project}</strong> to employee <strong>{user}</strong>.</p>

    <h3>📁 Employee Details:</h3>
    <ul>
        <li><strong>Employee Name:</strong> {users.first_name} {users.last_name}</li>
        <li><strong>Employee ID:</strong> {users.emp_id}</li>
        <li><strong>Role:</strong> {role}</li>
    </ul>

    <p>Please review and approve the assignment if everything looks good.</p>

    <p style="margin-top: 30px;">Regards,<br>C2DeVal System Notification</p>
    """


def html_description_otp(otp: str):
    return f"""
    <h2 style="color: #dc3545;">🔐 Email Verification Required</h2>
    <p>Dear User,</p>

    <p>To complete your verification process, please use the following One-Time Password (OTP):</p>

    <h1 style="color: #000; background-color: #f0f0f0; padding: 10px; display: inline-block;">{otp}</h1>

    <p>This OTP is valid for the next 10 minutes.</p>
    <p>If you didn’t request this, please ignore this email.</p>

    <p style="margin-top: 30px;">Regards,<br>C2DeVal Security Team</p>
    """

def user_account_created_template(name: str):
    return f"""
    <h2 style="color: #007bff;">🎉 Welcome to C2DeVal!</h2>
    <p>Dear {name},</p>

    <p>We’re excited to let you know that your account has been <strong>successfully created</strong>.</p>
    <p>You can now log in to your account and start using the platform.</p>
    <p style="margin-top: 30px;">Regards,<br>C2DeVal Team</p>
    """

