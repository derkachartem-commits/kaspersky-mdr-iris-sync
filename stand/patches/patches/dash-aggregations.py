P='/iriswebapp/app/datamgmt/custom_dashboard/named_aggregations.py'
src=open(P).read()
if '_cases_open_total' in src:
    print('already'); raise SystemExit
new = '''

def _cases_open_total(timeframe, filters: ComputedFilters) -> Optional[float]:
    """Count of cases currently open (status_id = 0)."""
    stmt = select(func.count(Cases.case_id)).where(Cases.status_id == 0)
    value = db.session.execute(stmt).scalar()
    return float(value) if value is not None else None

'''
marker='_NAMED_AGGREGATIONS: Dict[str, Callable[..., Optional[float]]] = {'
src=src.replace(marker, new.strip('\n')+'\n\n\n'+marker,1)
src=src.replace("    'cases_avg_close_hours': _cases_avg_close_hours,\n}", "    'cases_avg_close_hours': _cases_avg_close_hours,\n    'cases_open_total': _cases_open_total,\n}",1)
src=src.replace("        {'name': 'cases_avg_close_hours', 'label': 'Mean case closure time (hours)', 'value_format': 'number'},",
 "        {'name': 'cases_avg_close_hours', 'label': 'Mean case closure time (hours)', 'value_format': 'number'},\n        {'name': 'cases_open_total', 'label': 'Open cases total', 'value_format': 'number'},",1)
open(P,'w').write(src)
print('ok', '_cases_open_total' in src)
