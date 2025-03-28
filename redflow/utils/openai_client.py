#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenAI Client for RedFlow
Handles interactions with OpenAI API
"""

import os
import logging
import json
import time
from typing import Optional, Dict, Any, List, Union
import requests

class OpenAIClient:
    """
    Client for interacting with OpenAI API
    """
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        """
        Initialize the OpenAI client
        
        Args:
            api_key: OpenAI API key
            model: Model to use for completions
        """
        self.api_key = api_key
        self.model = model
        self.available = self._check_api_key()
        self.logger = logging.getLogger("openai_client")
        
    def _check_api_key(self) -> bool:
        """
        Check if the API key is valid
        
        Returns:
            True if API key is valid, False otherwise
        """
        return self.api_key is not None and len(self.api_key) > 10
    
    def get_completion(self, prompt: str, temperature: float = 0.3, max_tokens: int = 2048) -> Optional[str]:
        """
        Get a completion from OpenAI API
        
        Args:
            prompt: Prompt to send to OpenAI
            temperature: Temperature for the model
            max_tokens: Maximum tokens to generate
            
        Returns:
            Completion text or None if error
        """
        if not self.available:
            self.logger.warning("OpenAI API key is not available")
            return None
            
        # Log request parameters
        self.logger.info(f"Sending request to OpenAI API (model: {self.model}, temperature: {temperature})")
        
        try:
            # Create API request
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert specializing in offensive security, penetration testing, and exploit development, with extensive knowledge of Kali Linux."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            # Send API request
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            # Handle API response
            if response.status_code == 200:
                response_data = response.json()
                completion = response_data["choices"][0]["message"]["content"]
                return completion
            else:
                # Log error
                self.logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                
                # If rate limited, try again with exponential backoff
                if response.status_code == 429:
                    self.logger.warning("Rate limited by OpenAI API, waiting and retrying...")
                    time.sleep(2)
                    return self.get_completion(prompt, temperature, max_tokens)
                    
                return None
                
        except Exception as e:
            self.logger.error(f"Error in OpenAI API request: {str(e)}")
            return None
    
    def generate_image(self, prompt: str, size: str = "1024x1024") -> Optional[str]:
        """
        Generate an image with DALL-E
        
        Args:
            prompt: Prompt for image generation
            size: Image size (1024x1024, 512x512, or 256x256)
            
        Returns:
            URL of generated image or None if error
        """
        if not self.available:
            self.logger.warning("OpenAI API key is not available")
            return None
            
        # Log request
        self.logger.info(f"Sending image generation request to OpenAI API")
        
        try:
            # Create API request
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            
            data = {
                "prompt": prompt,
                "n": 1,
                "size": size
            }
            
            # Send API request
            response = requests.post(
                "https://api.openai.com/v1/images/generations",
                headers=headers,
                json=data
            )
            
            # Handle API response
            if response.status_code == 200:
                response_data = response.json()
                image_url = response_data["data"][0]["url"]
                return image_url
            else:
                # Log error
                self.logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error in OpenAI API request: {str(e)}")
            return None 