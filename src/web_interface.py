from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import json
import importlib
import threading
import time

# Import the variables module which contains all the settings
import variables

# For IP blocking management
from persistence.ip_blocking import blocked_ips, save_blocked_ips

app = Flask(__name__, template_folder='templates')
app.secret_key = 'waf_secret_key'  # Required for flash messages

# Keep track of the original values to highlight changes
original_values = {}
for var in dir(variables):
    if not var.startswith('__'):
        original_values[var] = getattr(variables, var)

@app.route('/')
def index():
    """Main page showing current settings and options"""
    # Get current values of all variables
    settings = {}
    for var in dir(variables):
        if not var.startswith('__'):
            settings[var] = getattr(variables, var)
    
    # Count number of blocked IPs
    blocked_count = len(blocked_ips)
    
    # Get log file sizes
    log_sizes = {
        'requests': get_file_size(variables.REQUEST_LOG_PATH),
        'responses': get_file_size(variables.RESPONSE_LOG_PATH),
        'pcap': get_file_size(variables.PCAP_LOG_PATH),
        'blocked_ips': get_file_size(variables.BLOCKED_IPS_FILE)
    }
    
    return render_template('index.html', 
                          settings=settings, 
                          original_values=original_values,
                          blocked_count=blocked_count,
                          log_sizes=log_sizes)

@app.route('/update_settings', methods=['POST'])
def update_settings():
    """Update WAF settings"""
    changes = []
    
    for key, value in request.form.items():
        if hasattr(variables, key):
            try:
                old_value = getattr(variables, key)
                # Determine the type of the original value and convert accordingly
                orig_type = type(old_value)
                if orig_type == int:
                    new_value = int(value)
                elif orig_type == float:
                    new_value = float(value)
                elif orig_type == bool:
                    new_value = value.lower() == 'true'
                elif orig_type == list:
                    # For simplicity, assume comma-separated values for lists
                    new_value = [item.strip() for item in value.split(',')]
                else:
                    new_value = value
                
                setattr(variables, key, new_value)
                changes.append(f"{key}: {old_value} → {new_value}")
                flash(f'Successfully updated {key} to {new_value}', 'success')
            except Exception as e:
                flash(f'Error updating {key}: {str(e)}', 'error')
    
    # Update the original values dictionary
    for var in dir(variables):
        if not var.startswith('__'):
            original_values[var] = getattr(variables, var)
    
    # Log the changes for debugging
    if changes:
        print("Settings updated:")
        for change in changes:
            print(f"  {change}")
            
    return redirect(url_for('index'))

@app.route('/reset_logs', methods=['POST'])
def reset_logs():
    """Reset log files"""
    try:
        log_type = request.form.get('log_type', 'all')
        
        if log_type == 'requests' or log_type == 'all':
            clear_file(variables.REQUEST_LOG_PATH)
            flash('Request logs cleared successfully', 'success')
            
        if log_type == 'responses' or log_type == 'all':
            clear_file(variables.RESPONSE_LOG_PATH)
            flash('Response logs cleared successfully', 'success')
            
        if log_type == 'pcap' or log_type == 'all':
            clear_file(variables.PCAP_LOG_PATH)
            flash('PCAP logs cleared successfully', 'success')
    except Exception as e:
        flash(f'Error clearing logs: {str(e)}', 'error')
        
    return redirect(url_for('index'))

@app.route('/clear_blocked_ips', methods=['POST'])
def clear_blocked_ips():
    """Clear blocked IPs"""
    try:
        blocked_ips.clear()
        save_blocked_ips()
        flash('Blocked IPs cleared successfully', 'success')
    except Exception as e:
        flash(f'Error clearing blocked IPs: {str(e)}', 'error')
        
    return redirect(url_for('index'))

@app.route('/view_blocked_ips')
def view_blocked_ips():
    """View blocked IPs with time remaining"""
    current_time = time.time()
    formatted_ips = {}
    
    for key, block_time in blocked_ips.items():
        time_left = block_time - current_time
        if time_left > 0:
            # Parse the key which is in format "ip:domain"
            parts = key.split(':', 1)
            ip = parts[0]
            domain = parts[1] if len(parts) > 1 else 'unknown'
            
            # Format time left in minutes and seconds
            minutes = int(time_left // 60)
            seconds = int(time_left % 60)
            time_str = f"{minutes}m {seconds}s"
            
            formatted_ips[key] = {
                'ip': ip,
                'domain': domain,
                'time_left': time_str,
                'raw_time_left': time_left
            }
    
    return render_template('blocked_ips.html', blocked_ips=formatted_ips)

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    """Unblock a specific IP"""
    try:
        key = request.form.get('key')
        if key in blocked_ips:
            del blocked_ips[key]
            save_blocked_ips()
            flash(f'Successfully unblocked {key}', 'success')
        else:
            flash(f'IP {key} not found in blocked list', 'error')
    except Exception as e:
        flash(f'Error unblocking IP: {str(e)}', 'error')
        
    return redirect(url_for('view_blocked_ips'))

def get_file_size(filepath):
    """Get the size of a file in human-readable format"""
    try:
        if os.path.exists(filepath):
            size_bytes = os.path.getsize(filepath)
            # Convert to KB, MB, etc.
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.2f} TB"
        return "0 B"
    except Exception:
        return "Error"

def clear_file(filepath):
    """Clear the contents of a file"""
    with open(filepath, 'w') as f:
        pass

def start_web_server():
    """Start the web server in a separate thread"""
    app.run(host='0.0.0.0', port=80, debug=False)

def run_web_interface():
    """Start the web interface in a separate thread"""
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True
    web_thread.start()
    print("Web interface started on port 80")
    return web_thread

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
