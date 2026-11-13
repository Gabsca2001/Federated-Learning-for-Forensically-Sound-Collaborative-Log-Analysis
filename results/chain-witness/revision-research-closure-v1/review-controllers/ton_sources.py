"""Retrieve auditable public mirrors without treating them as official full captures."""
from pathlib import Path
import hashlib
import json
import urllib.request
import zipfile

root = Path.cwd() / 'artifacts/revision-research-closure-v1'
dest = root / 'ton-iot-sources'
dest.mkdir(exist_ok=False)

def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent':'Academic ToN-IoT compatibility audit'})
    with urllib.request.urlopen(request, timeout=40) as response:
        return response.read()

metadata = json.loads((root/'zenodo-metadata.json').read_bytes())
for ds in ['codymlewis/TON_IoT_network','m-hesam-moradian/ToN_IoT_Train_Test_datasets']:
    try:
        data = fetch(f'https://huggingface.co/api/datasets/{ds}/tree/main?recursive=true&limit=1000')
        (dest/(ds.split('/')[0]+'-tree.json')).write_bytes(data)
        print(json.dumps({'dataset':ds,'files':[(x['path'],x.get('size')) for x in json.loads(data)]}),flush=True)
    except Exception as e:
        print(json.dumps({'dataset':ds,'error':str(e)}),flush=True)

item = next(x for x in metadata['files'] if x['key']=='Ton_Iot.zip')
target = dest/'Ton_Iot-zenodo-mirror.zip'
assert item['size'] < 200_000_000
request = urllib.request.Request(item['links']['self'], headers={'User-Agent':'Academic ToN-IoT compatibility audit'})
with urllib.request.urlopen(request, timeout=50) as response, target.open('xb') as stream:
    while block := response.read(1024*1024):
        stream.write(block)
actual_md5 = hashlib.md5(target.read_bytes()).hexdigest()
assert 'md5:'+actual_md5 == item['checksum'], (actual_md5,item['checksum'])
with zipfile.ZipFile(target) as archive:
    files = [{'name':x.filename,'bytes':x.file_size} for x in archive.infolist()]
    for entry in archive.infolist():
        p = Path(entry.filename)
        assert not p.is_absolute() and '..' not in p.parts
    archive.extractall(dest/'zenodo-mirror')
record = {'origin':item['links']['self'],'mirror_record_doi':'10.5281/zenodo.19367312',
          'record_checksum_verified':item['checksum'],'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
          'archive_bytes':target.stat().st_size,'contents':files,
          'publisher_original_release_identity_verified':False,
          'interpretation':'Research mirror; not evidence of complete official Zeek capture coverage.'}
(dest/'acquisition.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
