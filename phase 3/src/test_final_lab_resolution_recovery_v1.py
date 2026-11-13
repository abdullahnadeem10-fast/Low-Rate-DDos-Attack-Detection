import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from final_lab_resolution_recovery_v1 import IMAGE,identity,pretraffic_failure,ResolutionBridge,collector


class ReferenceRecovery(unittest.TestCase):
    def test_exact_image_identity_can_pass(self):
        item=dict(Id=IMAGE,RepoDigests=['httpd@'+IMAGE],Architecture='amd64',Os='linux',RootFS={'Layers':['sha256:layer']})
        self.assertEqual(identity(item)['id'],IMAGE)

    def test_mutable_tag_or_different_content_cannot_pass(self):
        item=dict(Id='sha256:different',RepoDigests=['httpd@'+IMAGE],Architecture='amd64',Os='linux',RootFS={'Layers':['layer']})
        with self.assertRaisesRegex(ValueError,'content identity'):identity(item)

    def test_wrong_platform_or_missing_layers_cannot_pass(self):
        item=dict(Id=IMAGE,RepoDigests=['httpd@'+IMAGE],Architecture='arm64',Os='linux',RootFS={'Layers':[]})
        with self.assertRaisesRegex(ValueError,'platform'):identity(item)

    def test_inspect_maps_only_original_exact_reference(self):
        calls=[]
        def original(*args,**kwargs):calls.append(args);return SimpleNamespace(stdout='')
        bridge=ResolutionBridge(original);bridge('image','inspect',collector.WEB_IMAGE);bridge('image','inspect',collector.TOOLS)
        self.assertEqual(calls,[('image','inspect',IMAGE),('image','inspect',collector.TOOLS)])

    def test_overlay_changes_only_web_image_without_mutating_original(self):
        calls=[]
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)/'compose.json';config={'services':{'web':{'image':collector.WEB_IMAGE,'ports_forbidden':True}},'networks':{'internal':True}};base.write_text(json.dumps(config))
            bridge=ResolutionBridge(lambda *args,**kwargs:calls.append(args));bridge('compose','-p','fixture','-f',str(base),'up','--pull','never')
            self.assertEqual(json.loads(base.read_text()),config)
            self.assertEqual(json.loads(base.with_name('image_resolution_overlay_v1.json').read_text()),{'services':{'web':{'image':IMAGE}}})
            self.assertEqual(calls[0][-3:],('up','--pull','never'));self.assertEqual(calls[0].count('-f'),2)

    def test_modified_overlay_or_override_chain_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)/'compose.json';base.write_text(json.dumps({'services':{'web':{'image':collector.WEB_IMAGE}}}))
            base.with_name('image_resolution_overlay_v1.json').write_text(json.dumps({'services':{'web':{'image':'other'}}}))
            bridge=ResolutionBridge(lambda *a,**k:None)
            with self.assertRaisesRegex(ValueError,'overlay changed'):bridge('compose','-f',str(base),'config')
            with self.assertRaisesRegex(ValueError,'override chain'):bridge('compose','-f',str(base),'-f','other','up')

    def test_actual_runtime_web_content_must_match(self):
        item=dict(Image='sha256:other',Config={'Labels':{'com.docker.compose.service':'web'}})
        bridge=ResolutionBridge(lambda *a,**k:SimpleNamespace(stdout=json.dumps([item])))
        with self.assertRaisesRegex(ValueError,'container content'):bridge('inspect','container')

    def test_only_no_capture_pretraffic_failure_is_recoverable(self):
        failure=dict(unit_id='final-b-014',state='failed_preserved',error_type='CalledProcessError',error=f"'image', 'inspect', '{collector.WEB_IMAGE}'")
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.assertEqual(pretraffic_failure({'attempts':[failure]},root),failure)
            (root/'final-b-014').mkdir()
            with self.assertRaisesRegex(ValueError,'capture artifacts'):pretraffic_failure({'attempts':[failure]},root)

    def test_other_failed_unit_requires_new_review(self):
        f=dict(unit_id='final-a-038',state='failed_preserved',error_type='CalledProcessError',error='different')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'exact pre-traffic'):pretraffic_failure({'attempts':[f]},Path(d))


if __name__=='__main__':unittest.main()
