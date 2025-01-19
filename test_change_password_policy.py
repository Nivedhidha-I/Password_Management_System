import unittest
import requests

class TestChangePasswordPolicyEndpoint(unittest.TestCase):
    def setUp(self):
        self.url = "http://127.0.0.1:5000/change_policy"
    
    def test_change_policy_success(self):
        response = requests.post(self.url+"?app_id=2&length=20")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Application password policy updated successfully.", response.text)
        print("Policy Row has been changed successfully.")

    def test_change_policy_not_found(self):
        response = requests.post(self.url+"?app_id=999&not_include=ab")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Application password policy with app_id 999 not found.", response.text)
        print("Policy Row doesn't exist.")

    def test_invalid_app_id(self):
        response = requests.post(self.url+"?app_id=invalid&cap=3")
        self.assertEqual(response.status_code, 400)
        print("The app_id is invalid.")
        
    def test_invalid_policy_parameters(self):
        response = requests.post(self.url+"?app_id=2&length=-1")
        self.assertEqual(response.status_code, 400)
        self.assertIn("The password policy is incorrect.", response.text)
        print("The input parameters are invalid.")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(TestChangePasswordPolicyEndpoint('test_change_policy_success')) 
    suite.addTest(TestChangePasswordPolicyEndpoint('test_change_policy_not_found'))
    suite.addTest(TestChangePasswordPolicyEndpoint('test_invalid_app_id'))
    suite.addTest(TestChangePasswordPolicyEndpoint('test_invalid_policy_parameters'))

    runner = unittest.TextTestRunner()
    runner.run(suite) 