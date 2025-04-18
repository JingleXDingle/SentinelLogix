import win32evtlog 
import win32security

def enable_privileges(privilege_name):
    "Enable a specific privilege for the current process."

def collect_event_logs(log_type="Security" , server="localhost"):
    """
    Collects Windows Event Logs from the specified log type.
    
    :param log_type: The type of log to collect (e.g., "System", "Application", "Security").
    :param server: The server to collect logs from (default is localhost).
    """
    try:
        # Open the event log
        log_handle = win32evtlog.OpenEventLog(server, log_type)
        
        # Get the total number of records
        total_records = win32evtlog.GetNumberOfEventLogRecords(log_handle)
        print(f"Total records in {log_type} log: {total_records}")
        
        # Read the event log
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        
        # Process each event
        for event in events:
            print(f"Event ID: {event.EventID}, Source: {event.SourceName}, Time: {event.TimeGenerated}")
        
        # Close the event log
        win32evtlog.CloseEventLog(log_handle)
    
    except Exception as e:
        print(f"Error accessing event logs: {e}")

# Example usage
if __name__ == "__main__":
    collect_event_logs(log_type="Security") 
    
