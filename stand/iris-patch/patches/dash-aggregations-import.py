P='/iriswebapp/app/datamgmt/custom_dashboard/named_aggregations.py'
src=open(P).read()
if 'from app.models.cases import Cases' not in src:
    src=src.replace('from app.models.alerts import Alert, AlertCaseAssociation, AlertResolutionStatus, AlertStatus',
                    'from app.models.alerts import Alert, AlertCaseAssociation, AlertResolutionStatus, AlertStatus\nfrom app.models.cases import Cases',1)
    open(P,'w').write(src)
print('import ok', 'from app.models.cases import Cases' in open(P).read())
