#!/usr/bin/env python3
"""
Push Token Analyzer - v1.1
===========================

A Python script to analyze push notification tokens and infer information
about the provider, platform, and characteristics based on token format.

This tool is designed for OSINT investigators and security researchers to
quickly identify the source and nature of push tokens.

Author: HawkEyes OSINT - https://hawk-eyes.io

Usage:
1.  Download the script from GitHub: [GitHub URL] (replace with your repo URL)
2.  Make the script executable: chmod +x push_token_analyzer.py
3.  Run the script: ./push_token_analyzer.py <token> [json]

   -  <token>: The push token to analyze (required)
   -  [json]: Optional - output in JSON format (default: text)

Example:
./push_token_analyzer.py d4c3b2a1e5f6789012345678901234567890abcdef1234567890abcdef123456
./push_token_analyzer.py eQkAAABbGGM:APA91bF1234567890abcdef json

Limitations:
- Analysis is based on format patterns and is not guaranteed to be accurate.
- Push tokens are opaque identifiers - no user/device data is extractable.
- Tokens can expire, be invalidated, or change format without notice.
- Use responsibly and in compliance with privacy regulations.
"""

import re
import json
import sys
from urllib.parse import urlparse

def analyze_push_token(token):
    """
    Analyze a push token and return inferences about its provider and characteristics.
    
    Args:
        token (str): The push token to analyze
        
    Returns:
        dict: Dictionary containing inferences about the token
    """
    
    if not token or not isinstance(token, str):
        return {"error": "Invalid token provided"}
    
    token = token.strip()
    inferences = {
        "token_length": len(token),
        "provider": "Unknown",
        "platform": "Unknown",
        "environment": "Unknown",
        "token_type": "Unknown",
        "characteristics": [],
        "confidence": "Low"
    }
    
    # APNs Token Detection (64-character hexadecimal)
    if re.match(r'^[a-fA-F0-9]{64}$', token):
        inferences.update({
            "provider": "Apple Push Notification Service (APNs)",
            "platform": "iOS/macOS/watchOS/tvOS",
            "token_type": "Device Token",
            "confidence": "High",
            "characteristics": [
                "32-byte binary value represented as hex",
                "Tied to specific app and device combination",
                "Opaque identifier - no extractable metadata"
            ]
        })
    
    # FCM Token Detection (long base64-like with colons/dashes)
    elif ':' in token and len(token) > 100:
        inferences.update({
            "provider": "Firebase Cloud Messaging (FCM)",
            "platform": "Android/Web",
            "token_type": "Registration Token",
            "confidence": "High",
            "characteristics": [
                "Base64-encoded with delimiters",
                "Refreshed periodically for security",
                "Tied to app instance on device"
            ]
        })
        
        # Check for common FCM prefixes
        if token.startswith('APA91b') or 'APA91b' in token:
            inferences["characteristics"].append("Contains APA91b prefix (common in FCM)")
    
    # Web Push Token Detection (URL-based)
    elif token.startswith('https://'):
        parsed_url = urlparse(token)
        inferences.update({
            "token_type": "Web Push Endpoint",
            "platform": "Web Browser",
            "confidence": "High"
        })
        
        if 'fcm.googleapis.com' in token:
            inferences.update({
                "provider": "Firebase Cloud Messaging (Web Push)",
                "characteristics": [
                    "Google Cloud Messaging for web push",
                    "Chrome/Chromium-based browser likely"
                ]
            })
        elif 'mozilla.com' in token:
            inferences.update({
                "provider": "Mozilla Push Service",
                "characteristics": ["Firefox browser"]
            })
        elif 'windows.com' in token or 'microsoft.com' in token:
            inferences.update({
                "provider": "Windows Push Notification Service",
                "characteristics": ["Microsoft Edge or Windows app"]
            })
    
    # Huawei Push Kit Detection (similar to FCM but may have different patterns)
    elif len(token) > 100 and re.match(r'^[A-Za-z0-9_-]+$', token):
        inferences.update({
            "provider": "Possibly Huawei Push Kit or other Android push service",
            "platform": "Android (Huawei devices)",
            "token_type": "Push Token",
            "confidence": "Medium",
            "characteristics": [
                "Long alphanumeric string",
                "Could be Huawei Push Kit or other Android push service",
                "Requires additional context for definitive identification"
            ]
        })
    
    # Short tokens (possibly legacy or custom)
    elif len(token) < 50:
        inferences.update({
            "provider": "Unknown/Custom Push Service",
            "token_type": "Short Token",
            "confidence": "Low",
            "characteristics": [
                "Unusually short for modern push tokens",
                "Possibly legacy system or custom implementation"
            ]
        })
    
    # Very long tokens without clear patterns
    elif len(token) > 200:
        inferences.update({
            "token_type": "Long Token",
            "characteristics": [
                "Unusually long token",
                "Possibly custom implementation or encoded data"
            ]
        })
    
    # Add general characteristics based on token analysis
    if re.match(r'^[a-fA-F0-9]+$', token):
        inferences["characteristics"].append("Pure hexadecimal format")
    elif re.match(r'^[A-Za-z0-9+/]+=*$', token):
        inferences["characteristics"].append("Base64-encoded format")
    elif re.match(r'^[A-Za-z0-9_-]+$', token):
        inferences["characteristics"].append("URL-safe base64 or alphanumeric format")
    
    return inferences

def print_analysis(analysis):
    """
    Print a formatted analysis of the push token.
    
    Args:
        analysis (dict): The analysis dictionary returned by analyze_push_token()
    """
    print(f"\n{'='*60}")
    print(f"PUSH TOKEN ANALYSIS")
    print(f"{'='*60}")
    print(f"Token: {analysis['token'][:50]}{'...' if len(analysis['token']) > 50 else ''}")
    print(f"{'='*60}")
    
    if "error" in analysis:
        print(f"ERROR: {analysis['error']}")
        return
    
    print(f"Provider: {analysis['provider']}")
    print(f"Platform: {analysis['platform']}")
    print(f"Token Type: {analysis['token_type']}")
    print(f"Token Length: {analysis['token_length']} characters")
    print(f"Confidence: {analysis['confidence']}")
    
    if analysis['characteristics']:
        print(f"\nCharacteristics:")
        for i, char in enumerate(analysis['characteristics'], 1):
            print(f"  {i}. {char}")
    
    print(f"\n{'='*60}")
    print("IMPORTANT NOTES:")
    print("• Push tokens are opaque identifiers - no user/device data extractable")
    print("• Analysis based on format patterns - not guaranteed to be accurate")
    print("• Tokens can expire, be invalidated, or change format without notice")
    print("• Use responsibly and in compliance with privacy regulations")
    print(f"{'='*60}\n")

def main():
    """
    Main function to run the push token analyzer.
    """
    print("Push Token Analyzer v1.1")
    print("HawkEyes OSINT - https://hawk-eyes.io")
    print("="*50)
    
    # Check for command line arguments
    if len(sys.argv) < 2:
        print("Error: Missing push token argument.")
        print("Usage: ./push_token_analyzer.py <token> [json]")
        print("Example: ./push_token_analyzer.py d4c3b2a1e5f6789012345678901234567890abcdef1234567890abcdef123456")
        sys.exit(1)
    
    token = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else "text"
    
    # Analyze the token
    analysis = analyze_push_token(token)
    analysis['token'] = token  # Store the token in the analysis dict
    
    if output_format.lower() == "json":
        print(json.dumps(analysis, indent=2))
    else:
        print_analysis(analysis)

if __name__ == "__main__":
    main()