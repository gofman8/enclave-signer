#!/usr/bin/env python3
# Testing branch only; uses the existing open-source IAM simulator process.
import argparse,hashlib,importlib.util,json,pathlib,shutil,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description='Independent IAM simulation of deployment lifecycle and full-role restrictions')
parser.add_argument('--node',default=shutil.which('node'))
parser.add_argument('--output',type=pathlib.Path,default=ROOT/'.artifacts/kms-e2e/deployment-policy-checks.json')
args=parser.parse_args()
if not args.node: parser.error('Node.js is required (or pass --node PATH)')
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('deployment',ROOT/'deploy/validate-swap-kms-deployment.py')
def measurement(label):
    return hashlib.sha384(label.encode()).hexdigest()


def approval(phase="transition"):
    images = [dict(eif="bootstrap.eif", pcr_file="bootstrap-PCR.json", sha256=hashlib.sha256(b"bootstrap").hexdigest(), pcr0=measurement("bootstrap"), mode="bootstrap", expected_evm_address=""), dict(eif="restore.eif", pcr_file="restore-PCR.json", sha256=hashlib.sha256(b"restore").hexdigest(), pcr0=measurement("restore"), mode="restore", expected_evm_address="0x7d024ab55b3b8a48d252fed98a48efbc559e2c31")]
    if phase == "bootstrap":
        images = images[:1]
    elif phase == "restore":
        images = images[1:]
    return dict(version=1, phase=phase, approved_by="release-reviewer", approval_reference="release-42", account_id="947263850162", signer_role="swap-signer", key_admin_role="swap-key-admin", key_arn="arn:aws:kms:eu-central-1:947263850162:key/dae39a52-e6c4-4ec9-87db-cccf8d7a0912", region="eu-central-1", seed_id="swap-signer-1", bitcoin_network="bitcoin", bucket="swap-seed-custody", object_key="swaps/signer-1/seed.kms", images=images)

node=args.node
proc=subprocess.Popen([node,str(ROOT/'testing/kms/policy-simulator.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
results=[]
def check(name,expected,action,resource,context,resource_policy,role_policy,principal,account):
 request={'request':{'principal':principal,'action':action,'resource':{'resource':resource,'accountId':account},'contextVariables':context},'identityPolicies':[{'name':'accidentally-broad-identity','policy':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]}},{'name':'dedicated-seed-role','policy':role_policy}],'resourcePolicy':resource_policy or {'Version':'2012-10-17','Statement':[]},'serviceControlPolicies':[],'resourceControlPolicies':[]}
 proc.stdin.write(json.dumps(request)+'\n');proc.stdin.flush(); verdict=json.loads(proc.stdout.readline())
 passed=verdict.get('resultType')!='error' and (verdict.get('result')=='Allowed')==expected
 results.append({'name':name,'expected_allowed':expected,'passed':passed,'verdict':verdict})
try:
 for phase in ['bootstrap','transition','restore']:
  a=approval(phase);policies=m.rendered_policies(a);key,bucket,role=(policies[name] for name in m.POLICIES)
  bucket_arn='arn:aws:s3:::'+a['bucket'];obj=bucket_arn+'/'+a['object_key']
  context={'application':'utexo-enclave-signer','flow':'rgb-swap','seed_id':a['seed_id'],'bitcoin_network':'bitcoin'}
  ctx={'kms:EncryptionContextKeys':list(context),**{'kms:EncryptionContext:'+k:v for k,v in context.items()}}
  for principal in [f'arn:aws:iam::{a["account_id"]}:role/{a["signer_role"]}',f'arn:aws:sts::{a["account_id"]}:assumed-role/{a["signer_role"]}/session']:
   def c(name,expected,action,resource,context={},policy=None):check(phase+' '+principal+' '+name,expected,action,resource,context,policy,role,principal,a['account_id'])
   for mode,pcr in [('bootstrap',measurement('bootstrap')),('restore',measurement('restore')),('unapproved',measurement('other')),('debug','0'*96),('missing',None)]:
    for action in ['kms:GenerateDataKey','kms:Decrypt']:
     allowed=any(i['pcr0']==pcr for i in a['images']) and (action=='kms:Decrypt' or mode=='bootstrap')
     context=dict(ctx)
     if pcr:context['kms:RecipientAttestation:PCR0']=pcr
     c(mode+' '+action,allowed,action,a['key_arn'],context,key)
   for name in ['s3:PutBucketPublicAccessBlock','s3:PutBucketAcl','s3:PutBucketOwnershipControls','s3:PutEncryptionConfiguration','s3:PutReplicationConfiguration','s3:PutLifecycleConfiguration','s3:PutBucketVersioning']:
    c(name,False,name,bucket_arn,{'aws:SecureTransport':'true'},bucket)
   for name in ['s3:DeleteObject','s3:DeleteObjectVersion','s3:PutObjectAcl','s3:PutObjectVersionAcl','s3:UpdateObjectEncryption','s3:PutObjectRetention','s3:PutObjectLegalHold','s3:BypassGovernanceRetention','s3:PutObjectTagging','s3:DeleteObjectVersionTagging']:
    c(name,False,name,obj,{'aws:SecureTransport':'true'},bucket)
   c('read own blob',True,'s3:GetObject',obj,{'aws:SecureTransport':'true'},bucket)
   c('conditional create',True,'s3:PutObject',obj,{'aws:SecureTransport':'true','s3:if-none-match':'*'},bucket)
   c('unconditional overwrite',False,'s3:PutObject',obj,{'aws:SecureTransport':'true'},bucket)
   c('list dedicated bucket',True,'s3:ListBucket',bucket_arn,{'aws:SecureTransport':'true'},bucket)
   c('read other object',False,'s3:GetObject',obj+'-other',{'aws:SecureTransport':'true'},bucket)
   c('read other bucket',False,'s3:ListBucket',bucket_arn+'-other',{'aws:SecureTransport':'true'})
   c('decrypt other KMS key',False,'kms:Decrypt',a['key_arn']+'-other',dict(ctx,**{'kms:RecipientAttestation:PCR0':a['images'][0]['pcr0']}))
   c('assume administrator',False,'sts:AssumeRole',f'arn:aws:iam::{a["account_id"]}:role/{a["key_admin_role"]}')
   c('change role policy',False,'iam:PutRolePolicy',f'arn:aws:iam::{a["account_id"]}:role/{a["signer_role"]}')
   c('change account public access',False,'s3:PutAccountPublicAccessBlock','*')
finally:
 proc.stdin.close();proc.wait(timeout=30)
report={'scope':'Offline Cloud Copilot IAM simulator; actual rendered policies with broad identity allow plus dedicated role deny; no AWS calls','count':len(results),'passed':sum(r['passed'] for r in results),'cases':results}
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
for r in results:
 if not r['passed']:print(json.dumps(r))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
