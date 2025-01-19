import unittest
import requests

class TestGeneratePasswordEndpoint(unittest.TestCase):
    def setUp(self):
        self.url = "http://127.0.0.1:5000/generate_password"
    
    def test_generate_password_success(self):
        response = requests.post(self.url+"?app_id=1&user_id=2")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password generated successfully.", response.text)
        self.assertIn("The password is ", response.text)
        print("New Password: ", response.text.split("\n")[1][63:], sep="\"")
        
    def test_missing_app_id(self):
        response = requests.post(self.url+"?user_id=2")
        self.assertEqual(response.status_code, 400)
        self.assertIn("both app_id and user_id are required", response.text)
        print("The app_id is missing.")

    def test_missing_user_id(self):
        response = requests.post(self.url+"?app_id=1")
        self.assertEqual(response.status_code, 400)
        self.assertIn("both app_id and user_id are required", response.text)
        print("The user_id is missing.")
        
    def test_app_id_not_found(self):
        response = requests.post(self.url+"?app_id=999&user_id=2")
        self.assertEqual(response.status_code, 400)
        self.assertIn("app_id not registered in PMS", response.text)
        print("The app_id is not registered in PMS.")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(TestGeneratePasswordEndpoint('test_generate_password_success')) 
    suite.addTest(TestGeneratePasswordEndpoint('test_missing_app_id'))
    suite.addTest(TestGeneratePasswordEndpoint('test_missing_user_id'))
    suite.addTest(TestGeneratePasswordEndpoint('test_app_id_not_found'))

    runner = unittest.TextTestRunner()
    runner.run(suite) 