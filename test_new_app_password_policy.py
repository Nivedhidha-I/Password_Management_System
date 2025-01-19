import unittest
import requests

class TestNewAppPasswordPolicyEndpoint(unittest.TestCase):
    def setUp(self):
        self.url = "http://127.0.0.1:5000/add_new_policy"
    
    def test_new_policy_success(self):
        response = requests.post(self.url+"?app_name=AnotherApp&length=14&cap=2&small=4&num=3&special=1&not_include=Uu")
        self.assertEqual(response.status_code, 201)
        self.assertIn("New application password policy created successfully", response.text)
        print("Policy Row created successfully.")

    def test_existing_policy_failure(self):
        response = requests.post(self.url+"?app_name=AnotherApp&not_include=ab")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Policy already exists for the mentioned application.", response.text)
        print("Policy Row already exists.")

    def test_missing_app_name(self):
        response = requests.post(self.url+"?length=14&small=4&num=3")
        self.assertEqual(response.status_code, 400)
        self.assertIn("App name is required", response.text)
        print("The app name is missing.")
        
    def test_invalid_policy_parameters(self):
        response = requests.post(self.url+"?app_name=YetAnother&length=0&special=10")
        self.assertEqual(response.status_code, 400)
        self.assertIn("The password policy is incorrect.", response.text)
        print("The input parameters are invalid.")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(TestNewAppPasswordPolicyEndpoint('test_new_policy_success')) 
    suite.addTest(TestNewAppPasswordPolicyEndpoint('test_existing_policy_failure'))
    suite.addTest(TestNewAppPasswordPolicyEndpoint('test_missing_app_name'))
    suite.addTest(TestNewAppPasswordPolicyEndpoint('test_invalid_policy_parameters'))


    runner = unittest.TextTestRunner()
    runner.run(suite) 