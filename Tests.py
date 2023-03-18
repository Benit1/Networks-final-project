import unittest
from DHCP import  create_ip_list, IPs


class MyTestCase(unittest.TestCase):
    def test_create_ip_list(self):
        network = "192.168.1.0/24"
        create_ip_list(network)
        self.assertEqual(len(IPs), 256)
        self.assertIn("192.168.1.1", IPs)
        self.assertIn("192.168.1.254", IPs)
        self.assertNotIn("192.168.2.1", IPs)


if __name__ == '__main__':
    unittest.main()
