import unittest
from audit_monday_labels import audit_rows


class MondayAuditChecks(unittest.TestCase):
    def row(self,host='192.168.10.50',port='80',label='BENIGN'):
        return {'Source IP':'192.0.2.1','Source Port':'40000','Destination IP':host,
                'Destination Port':port,'Protocol':'6','Label':label,
                'Timestamp':'3/7/2017 9:00','Flow Duration':'1000'}

    def test_both_host_directions_are_inventoried(self):
        a=self.row(); b=self.row(host='205.174.165.68',port='443')
        b['Source IP'],b['Destination IP']=b['Destination IP'],b['Source IP']
        b['Source Port'],b['Destination Port']=b['Destination Port'],b['Source Port']
        r=audit_rows([a,b])
        self.assertEqual(r['published_web_host_coverage']['192.168.10.50']['port_80_occurrences'],1)
        self.assertEqual(r['published_web_host_coverage']['205.174.165.68']['port_443_occurrences'],1)
        self.assertFalse(r['matched_http_calibration_established'])

    def test_nonbenign_or_wrong_date_is_rejected(self):
        with self.assertRaises(ValueError): audit_rows([self.row(label='DDoS')])
        row=self.row(); row['Timestamp']='5/7/2017 9:00'
        with self.assertRaises(ValueError): audit_rows([row])


if __name__=='__main__': unittest.main(verbosity=2)
