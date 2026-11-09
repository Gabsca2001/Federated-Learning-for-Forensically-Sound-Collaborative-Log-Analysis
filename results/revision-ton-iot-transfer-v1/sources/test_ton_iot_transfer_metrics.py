import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('transfer_evaluation',Path(__file__).with_name('evaluate_ton_iot_transfer.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class MetricTests(unittest.TestCase):
    def test_confusion_and_balanced_accuracy(self):
        result=module.binary_metrics([0,0,1,1],[0,1,0,1],[.1,.9,.2,.8])
        self.assertEqual(result['confusion_matrix']['values'],[[1,1],[1,1]])
        self.assertEqual(result['balanced_accuracy'],.5)

    def test_missing_class_does_not_create_a_fake_zero_recall(self):
        result=module.binary_metrics([0,0],[0,0],[.1,.2])
        self.assertIsNone(result['attack_recall'])
        self.assertIsNone(result['balanced_accuracy'])
        self.assertIsNone(result['auroc'])

    def test_no_predicted_attack_is_distinct_from_no_true_attacks(self):
        result=module.binary_metrics([0,1],[0,0],[.1,.2])
        self.assertIsNone(result['attack_precision'])
        self.assertEqual(result['attack_recall'],0)
        self.assertEqual(result['attack_f1'],0)
        self.assertEqual(result['balanced_accuracy'],.5)


if __name__=='__main__':unittest.main()
