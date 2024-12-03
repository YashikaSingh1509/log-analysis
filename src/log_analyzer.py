import os
import re
from collections import Counter
import csv
from typing import List, Dict, Tuple

class LogAnalyzer:
    def __init__(self, log_file_path: str, failed_login_threshold: int = 3):
        """
        Initialize the LogAnalyzer with the log file path and failed login threshold.
        
        :param log_file_path: Path to the log file to be analyzed
        :param failed_login_threshold: Number of failed login attempts to flag as suspicious
        """
        self.log_file_path = log_file_path
        self.failed_login_threshold = failed_login_threshold
        self.log_entries: List[str] = []
        self.results_dir = os.path.join(os.path.dirname(os.path.dirname(log_file_path)), 'results')
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)

    def read_log_file(self) -> None:
        """
        Read the log file and store its entries.
        """
        try:
            with open(self.log_file_path, 'r') as file:
                self.log_entries = file.readlines()
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file_path} not found.")
            exit(1)

    def count_requests_per_ip(self) -> Dict[str, int]:
        """
        Count the number of requests for each IP address.
        
        :return: Dictionary of IP addresses and their request counts
        """
        # Improved regex to extract IP addresses with more precise matching
        ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
        ip_counts = Counter()
        
        for entry in self.log_entries:
            match = re.match(ip_pattern, entry)
            if match:
                ip = match.group(1)
                ip_counts[ip] += 1
        
        return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

    def find_most_accessed_endpoint(self) -> Tuple[str, int]:
        """
        Find the most frequently accessed endpoint.
        
        :return: Tuple of (endpoint, access count)
        """
        # Improved regex to extract endpoints with more precise matching
        endpoint_pattern = r'"(?:GET|POST) (/\w+)'
        endpoints = []
        
        for entry in self.log_entries:
            # Only count successful requests (status code 200)
            if ' 200 ' in entry:
                match = re.search(endpoint_pattern, entry)
                if match:
                    endpoints.append(match.group(1))
        
        endpoint_counts = Counter(endpoints)
        return max(endpoint_counts.items(), key=lambda x: x[1])

    def detect_suspicious_activity(self) -> Dict[str, int]:
        """
        Detect potential brute force login attempts.
        
        :return: Dictionary of suspicious IP addresses and their failed login attempt counts
        """
        # Improved regex to extract IP addresses from failed login attempts
        failed_login_pattern = r'^(\d+\.\d+\.\d+\.\d+).*"POST /login".*401'
        failed_logins = Counter()
        
        for entry in self.log_entries:
            match = re.match(failed_login_pattern, entry)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
        
        # Filter IPs with failed login attempts exceeding the threshold
        suspicious_ips = {ip: count for ip, count in failed_logins.items() 
                          if count >= self.failed_login_threshold}
        
        return dict(sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True))

    def save_results_to_csv(self, results: Dict) -> str:
        """
        Save analysis results to a CSV file.
        
        :param results: Dictionary containing analysis results
        :return: Path to the saved CSV file
        """
        csv_path = os.path.join(self.results_dir, 'log_analysis_results.csv')
        
        with open(csv_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            
            # Write Requests per IP section
            csv_writer.writerow(['Requests per IP'])
            csv_writer.writerow(['IP Address', 'Request Count'])
            for ip, count in results['requests_per_ip'].items():
                csv_writer.writerow([ip, count])
            
            csv_writer.writerow([])  # Add a blank row between sections
            
            # Write Most Accessed Endpoint section
            csv_writer.writerow(['Most Accessed Endpoint'])
            csv_writer.writerow(['Endpoint', 'Access Count'])
            csv_writer.writerow([results['most_accessed_endpoint'][0], 
                                  results['most_accessed_endpoint'][1]])
            
            csv_writer.writerow([])  # Add a blank row between sections
            
            # Write Suspicious Activity section
            csv_writer.writerow(['Suspicious Activity'])
            csv_writer.writerow(['IP Address', 'Failed Login Attempts'])
            for ip, count in results.get('suspicious_activity', {}).items():
                csv_writer.writerow([ip, count])
        
        return csv_path

    def analyze_log(self) -> Dict:
        """
        Perform complete log analysis and display results.
        
        :return: Dictionary of analysis results
        """
        # Read the log file
        self.read_log_file()
        
        # Perform analyses
        requests_per_ip = self.count_requests_per_ip()
        most_accessed_endpoint = self.find_most_accessed_endpoint()
        suspicious_activity = self.detect_suspicious_activity()
        
        # Prepare results dictionary
        results = {
            'requests_per_ip': requests_per_ip,
            'most_accessed_endpoint': most_accessed_endpoint,
            'suspicious_activity': suspicious_activity
        }
        
        # Display results
        print("Requests per IP Address:")
        print(f"{'IP Address':<20} {'Request Count':<15}")
        for ip, count in requests_per_ip.items():
            print(f"{ip:<20} {count:<15}")
        
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
        
        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
        if suspicious_activity:
            for ip, count in suspicious_activity.items():
                print(f"{ip:<20} {count:<25}")
        else:
            print("No suspicious activity detected.")
        
        # Save results to CSV
        csv_path = self.save_results_to_csv(results)
        print(f"\nResults have been saved to {csv_path}")
        
        return results

def main():
    # Get the directory of the current script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the path to the log file in the data directory
    log_file_path = os.path.join(os.path.dirname(current_dir), 'data', 'sample.log')
    
    # Create LogAnalyzer instance and analyze the log
    try:
        analyzer = LogAnalyzer(log_file_path, failed_login_threshold=3)
        results = analyzer.analyze_log()
        
        # Optional: Additional insights
        print("\nAdditional Insights:")
        print(f"Total Unique IP Addresses: {len(results['requests_per_ip'])}")
        print(f"Total Log Entries: {len(analyzer.log_entries)}")
        
        # Debug: Print raw log entries to verify parsing
        print("\nDebug - First few log entries:")
        for entry in analyzer.log_entries[:5]:
            print(entry.strip())
        
    except Exception as e:
        print(f"An error occurred during log analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()