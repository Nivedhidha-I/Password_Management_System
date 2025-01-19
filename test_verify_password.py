import unittest
import requests

class TestVerifyPasswordEndpoint(unittest.TestCase):
    def setUp(self):
        self.url = "http://127.0.0.1:5000/verify_password"
    
    def test_verify_password_success(self):
        response = requests.post(self.url+"?user_id=1&app_id=1&password=cL;3TXTK*Q?4MCK '.'FNxNN|0iGfS")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful", response.text)
        print("Authentication succeeded Successful")
        
    def test_verify_password_failure(self):
        response = requests.post(self.url+"?user_id=1&app_id=1&password=LLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Incorrect password", response.text)
        print("Authentication failed Successfully")

    def test_user_not_found(self):
        response = requests.post(self.url+"?user_id=999&app_id=1&password=cL;3TXTK*Q?4MCK '.'FNxNN|0iGfS")
        self.assertEqual(response.status_code, 404)
        self.assertIn("User or application not found", response.text)
        print("The user_id is from the database.")
        
    def test_missing_user_id(self):
        response = requests.post(self.url+"?app_id=1&password=cL;3TXTK*Q?4MCK '.'FNxNN|0iGfS")
        self.assertEqual(response.status_code, 400)
        self.assertIn("user_id, app_id, and password are required", response.text)
        print("The user_id is missing from the parameters.")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(TestVerifyPasswordEndpoint('test_verify_password_success')) 
    suite.addTest(TestVerifyPasswordEndpoint('test_verify_password_failure'))
    suite.addTest(TestVerifyPasswordEndpoint('test_user_not_found'))
    suite.addTest(TestVerifyPasswordEndpoint('test_missing_user_id'))

    runner = unittest.TextTestRunner()
    runner.run(suite) 