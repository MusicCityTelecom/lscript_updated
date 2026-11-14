import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from lazytoolkit import core, installers, integration, bridge, workflows
from lazytoolkit.pentest_patch import patch_menu
from lazytoolkit.profiles import PROFILES


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.stack=contextlib.ExitStack()
        self.stack.enter_context(patch.dict(os.environ,{'LSCRIPT_STATE_DIR':str(self.root/'state')}))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def tearDown(self):
        self.stack.close(); self.temp.cleanup()

    def archive(self,members):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:
            for name,content in members.items(): archive.writestr(name,content)
        return buffer.getvalue()

    def test_all_original_source_entries_retained(self):
        data=core.load_catalog(); counts={}
        for record in data['records']:
            for source in record['sources']:
                counts[source['suite']]=counts.get(source['suite'],0)+1
        self.assertEqual(counts['pentest-menu'],200)
        self.assertEqual(counts['BCHackTool'],21)
        self.assertEqual(counts['LScript'],100)

    def test_ids_are_unique(self):
        ids=[r['id'] for r in core.load_catalog()['records']]
        self.assertEqual(len(ids),len(set(ids)))

    def test_katana_projects_not_conflated(self):
        self.assertNotEqual(core.tool('katana')['id'],core.tool('katanaframework')['id'])
        self.assertIn('PowerScript',str(core.tool('katanaframework')['repositories']))

    def test_jadx_gui_is_action_not_duplicate_application(self):
        self.assertEqual(core.tool('jadx')['actions']['gui'],'jadx-gui')
        self.assertNotIn('jadxgui',[r['id'] for r in core.load_catalog()['records']])

    def test_profiles_only_use_known_tools(self):
        for ids in PROFILES.values():
            for key in ids: self.assertTrue(core.tool(key).get('recipe'),key)

    def test_existing_binary_preferred(self):
        record={'id':'fixture','commands':['fixture-tool'],'bindings':[]}
        with patch.object(core.shutil,'which',return_value='/usr/bin/fixture-tool'):
            self.assertEqual(core.resolve(record)[0],['/usr/bin/fixture-tool'])

    def test_reference_binding_is_not_execution_binding(self):
        record={'id':'fixture','commands':[],'bindings':[dict(command='source-viewer',kind='reference')]}
        with patch.object(core.shutil,'which',return_value='/usr/bin/source-viewer'):
            self.assertIsNone(core.resolve(record)[0])
            self.assertEqual(core.status(record),'source-only')

    def test_native_arguments_are_not_shell_interpreted(self):
        record={'id':'fixture','commands':['fixture-tool'],'bindings':[]}
        with patch.object(core.shutil,'which',return_value='/usr/bin/fixture-tool'),patch.object(core,'run') as run:
            core.execute(record,['a b','*','$(do-not-run)','literal;value'])
        self.assertEqual(run.call_args.args[0][1:],['a b','*','$(do-not-run)','literal;value'])

    def test_gui_needs_display(self):
        record={'id':'fixture','commands':['fixture-tool'],'bindings':[],'kind':'gui'}
        with patch.dict(os.environ,{},clear=True),patch.object(core.shutil,'which',return_value='/bin/fixture'):
            with self.assertRaisesRegex(core.LazyError,'graphical'): core.execute(record,[])

    def test_os_detection_for_debian_family(self):
        for name in ['kali','debian','ubuntu']:
            path=self.root/'os-release'; path.write_text(f'ID={name}\nVERSION_ID="test"\n')
            self.assertTrue(core.distro(path)['supported'])

    def test_other_os_not_claimed_supported(self):
        path=self.root/'os-release'; path.write_text('ID=fedora\n')
        self.assertFalse(core.distro(path)['supported'])

    def test_apt_unavailable_package_does_not_install(self):
        with patch.object(installers,'distro',return_value={'supported':True}), \
             patch.object(installers,'package_available',return_value=False),patch.object(installers,'run') as run:
            with self.assertRaisesRegex(core.LazyError,'Unavailable'): installers.install_apt(['fixture'])
        run.assert_not_called()

    def test_apt_rejects_unsupported_platform(self):
        with patch.object(installers,'distro',return_value={'supported':False}):
            with self.assertRaises(core.LazyError): installers.install_apt(['gdb'])

    def test_plan_has_no_install_side_effects(self):
        record=dict(id='fixture',name='Fixture',recipe={'kind':'apt','packages':['fixture']})
        with patch.object(installers,'resolve',return_value=(None,None)),patch.object(installers,'install_apt') as run:
            installers.install(record,dry_run=True)
        run.assert_not_called()

    def test_already_installed_skips_downloads(self):
        with patch.object(installers,'resolve',return_value=(['/bin/fixture'],'cli')),patch.object(installers,'download') as download:
            installers.install(dict(id='fixture',name='Fixture',recipe={'kind':'release'}))
        download.assert_not_called()

    def test_rejects_zip_path_traversal_before_writing(self):
        data=self.archive({'ordinary':'okay','../outside':'bad'})
        with self.assertRaises(core.LazyError): installers.safe_unzip(data,self.root)
        self.assertFalse((self.root/'ordinary').exists())

    def test_rejects_zip_symlink(self):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w') as archive:
            member=zipfile.ZipInfo('link'); member.external_attr=(stat.S_IFLNK|0o777)<<16
            archive.writestr(member,'/etc/passwd')
        with self.assertRaises(core.LazyError): installers.safe_unzip(buffer.getvalue(),self.root)

    def test_release_missing_checksum_does_not_download_binary(self):
        metadata={'tag_name':'fixture','assets':[{'name':'fixture.zip','browser_download_url':'https://example.test/binary','digest':None}]}
        recipe={'repository':'owner/repo','asset_pattern':r'fixture\.zip'}
        with patch.object(installers,'download',return_value=json.dumps(metadata).encode()) as fetch:
            with self.assertRaisesRegex(core.LazyError,'SHA-256'): installers.release_install({'id':'fixture'},recipe)
        self.assertEqual(fetch.call_count,1)

    def test_release_checksum_mismatch_does_not_extract(self):
        metadata={'tag_name':'fixture','assets':[{'name':'fixture.zip','browser_download_url':'https://example.test/binary','digest':'sha256:'+'0'*64}]}
        with patch.object(installers,'download',side_effect=[json.dumps(metadata).encode(),b'bad']),patch.object(installers,'safe_unzip') as extract:
            with self.assertRaisesRegex(core.LazyError,'mismatch'):
                installers.release_install({'id':'fixture'},{'repository':'owner/repo','asset_pattern':r'fixture\.zip'})
        extract.assert_not_called()

    def test_ghidra_reads_release_java_requirement(self):
        data=self.archive({'ghidra_fixture/ghidraRun':'#!/bin/sh\n',
                           'ghidra_fixture/Ghidra/application.properties':'application.java.min=21\n'})
        metadata={'tag_name':'fixture','assets':[{'name':'fixture.zip','browser_download_url':'https://example.test/binary',
                   'digest':'sha256:'+hashlib.sha256(data).hexdigest()}]}
        recipe=dict(repository='owner/repo',asset_pattern=r'fixture\.zip',entry_glob='*/ghidraRun',java_min=25)
        with patch.object(installers,'download',side_effect=[json.dumps(metadata).encode(),data]), \
             patch.object(installers,'java_home',return_value=self.root/'jdk') as java:
            installers.release_install({'id':'ghidra'},recipe)
        java.assert_called_once_with(21)
        self.assertTrue((self.root/'state/tools/ghidra/installed.json').is_file())

    def test_static_triage_does_not_execute_sample(self):
        sample=self.root/'sample'; sample.write_bytes(b'not executable')
        completed=subprocess.CompletedProcess([],0,stdout='fixture',stderr='')
        with patch.object(workflows.shutil,'which',return_value='/bin/fixture'), \
             patch.object(workflows.subprocess,'run',return_value=completed) as run:
            workflows.triage(sample,self.root/'report.json')
        for call in run.call_args_list: self.assertNotEqual(call.args[0][0],str(sample))
        report=json.loads((self.root/'report.json').read_text())
        self.assertEqual(report['sha256'],hashlib.sha256(sample.read_bytes()).hexdigest())

    def test_triage_does_not_overwrite_input(self):
        sample=self.root/'sample'; sample.write_bytes(b'preserve')
        with patch.object(workflows.shutil,'which',return_value=None):
            with self.assertRaises(core.LazyError): workflows.triage(sample,sample)
        self.assertEqual(sample.read_bytes(),b'preserve')

    def test_bridge_deduplicates_existing_commands(self):
        text='A|Responder|responder|root|First\nB|Responder|responder|root|Second\n'
        rows=bridge.merge(text,self.root)
        ids=[bridge.key_for(row[2]) for row in rows]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertEqual(sum(row[2]=='responder' for row in rows),1)

    def test_patch_is_repeatable(self):
        original=(core.PROJECT/'tests/fixtures/pentest-menu').read_text()
        patched=patch_menu(original)
        self.assertEqual(patch_menu(patched),patched)
        self.assertIn('INTEGRATED_STATUS',patched)

    def bash_harness(self):
        original=(core.PROJECT/'tests/fixtures/pentest-menu').read_text()
        body=patch_menu(original).split('if [[ "${1:-}" == "--install" ]]',1)[0]
        body+='\nterm_run() { shift; python3 -c "import json,sys; print(json.dumps(sys.argv[1:]))" "$@"; }\n'
        body+='run_tool fixture /bin/echo cli fixture\n'
        harness=self.root/'harness.sh'; harness.write_text(body)
        return harness

    def test_bash_argument_parser_preserves_quotes_empty_and_wildcard(self):
        env=dict(os.environ,PENTEST_MENU_INTEGRATION_DIR=str(self.root/'absent'))
        result=subprocess.run(['bash',str(self.bash_harness())],input='"two words" "*" "" "literal; $(not-run)"\n',
                              capture_output=True,text=True,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout.strip()),['/bin/echo','two words','*','','literal; $(not-run)'])

    def test_bash_invalid_quotes_do_not_launch(self):
        env=dict(os.environ,PENTEST_MENU_INTEGRATION_DIR=str(self.root/'absent'))
        result=subprocess.run(['bash',str(self.bash_harness())],input='"unfinished\n',capture_output=True,text=True,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('/bin/echo',result.stdout)

    def test_integration_and_rollback_preserve_existing_files(self):
        menu=self.root/'pentest-menu'
        original=(core.PROJECT/'tests/fixtures/pentest-menu').read_text()
        menu.write_text(original); menu.chmod(0o755)
        config=self.root/'.config/pentest-menu/tools.list'; config.parent.mkdir(parents=True)
        config.write_text('# keep my custom entries\n')
        untouched=self.root/'Desktop/Pentest/BCHackTool/custom-data'; untouched.parent.mkdir(parents=True); untouched.write_text('preserve')
        with patch.object(Path,'home',return_value=self.root): integration.integrate(menu,apply=True)
        self.assertIn('BEGIN PENTEST CATALOG INTEGRATION',menu.read_text())
        self.assertIn('# keep my custom entries',config.read_text())
        self.assertEqual(untouched.read_text(),'preserve')
        backup=next((self.root/'.local/state/lscript-updated/backups').iterdir())
        integration.rollback(backup)
        self.assertEqual(menu.read_text(),original)
        self.assertEqual(config.read_text(),'# keep my custom entries\n')

    def test_self_install_preserves_existing_l_command(self):
        binary=self.root/'.local/bin'; binary.mkdir(parents=True)
        existing=binary/'l'; existing.write_text('keep')
        with patch.object(Path,'home',return_value=self.root),patch.object(os,'geteuid',return_value=1000):
            integration.self_install()
        self.assertEqual(existing.read_text(),'keep')
        self.assertTrue((binary/'lazy').is_symlink())

    def test_integrated_bash_listing_uses_live_catalog_without_duplicates(self):
        menu=self.root/'pentest-menu'
        original=(core.PROJECT/'tests/fixtures/pentest-menu').read_text()
        menu.write_text(original); menu.chmod(0o755)
        with patch.object(Path,'home',return_value=self.root): integration.integrate(menu,apply=True)
        env=dict(os.environ,PENTEST_MENU_INTEGRATION_DIR=str(self.root/'.local/share/pentest-menu-integration'))
        result=subprocess.run(['bash',str(menu),'--list'],capture_output=True,text=True,env=env,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        lines=result.stdout.splitlines()[1:]
        commands=[line.split()[-1] for line in lines if line.strip()]
        canonical=[bridge.key_for(command) for command in commands]
        self.assertEqual(len(canonical),len(set(canonical)))
        self.assertEqual(len(canonical),len(core.load_catalog()['records']))


if __name__=='__main__': unittest.main()
