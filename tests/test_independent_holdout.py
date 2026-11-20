import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evaluation.independent_holdout import confusion, load_episodes


class IndependentHoldoutHarnessTests(unittest.TestCase):
    def test_confusion_matrix_math(self):
        result = confusion([('attack', True), ('attack', False),
                            ('benign', True), ('benign', False)])
        self.assertEqual(tuple(result[k] for k in ('tp', 'fp', 'fn', 'tn')),
                         (1, 1, 1, 1))
        self.assertEqual(result['f1'], 0.5)
        self.assertEqual(result['precision'], 0.5)
        self.assertEqual(result['recall'], 0.5)

    def test_no_positive_sample_has_undefined_recall(self):
        result = confusion([('benign', False)])
        self.assertIsNone(result['recall'])
        self.assertIsNone(result['precision'])
        self.assertIsNone(result['f1'])

    def test_duplicate_episode_ids_rejected(self):
        episode = {'episode_id': 'same', 'label': 'benign',
                   'events': [{'channel': 'Security', 'record_id': 1}]}
        with TemporaryDirectory() as d:
            path = Path(d) / 'episodes.jsonl'
            path.write_text(json.dumps(episode) + '\n' + json.dumps(episode), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                load_episodes(path)

    def test_unordered_record_ids_rejected(self):
        episode = {'episode_id': 'case1', 'label': 'benign',
                   'events': [{'channel': 'Security', 'record_id': 2},
                              {'channel': 'Security', 'record_id': 1}]}
        with TemporaryDirectory() as d:
            path = Path(d) / 'episodes.jsonl'
            path.write_text(json.dumps(episode), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'ascending'):
                load_episodes(path)


if __name__ == '__main__':
    unittest.main()
