"""按原始账本复算一次真实重启；缺少期限内实际清零观察时保留时效未验证。"""
import datetime as dt
import json


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def delta(later,earlier):
    return (dt.datetime.fromisoformat(later)-dt.datetime.fromisoformat(earlier)).total_seconds()


def build_reboot(base):
    folder=base/'remote/round3/reboot-01'
    paths=[base/'reboot-01.json',base/'post-reboot.json',folder/'command.json',
           folder/'restart-intent.json',folder/'boot-inventory.json',folder/'boot-observation.json',
           folder/'reboot-watch.jsonl',folder/'owner.jsonl',folder/'watchdog.jsonl',
           base/'remote/round3/stale-boot-02/ready.json',
           base/'remote/round3/stale-boot-02/owner.jsonl',
           base/'remote/round3/stale-boot-02/final.json']
    r=read(paths[0]);post=read(paths[1]);command=read(paths[2]);intent=read(paths[3])
    boot=read(paths[4]);observation=read(paths[5])
    watch=[json.loads(line) for line in paths[6].read_text().splitlines()]
    stale=[json.loads(line) for line in paths[10].read_text().splitlines()]
    task_path=base/'reboot-task-state.json';task=read(task_path);paths.append(task_path)
    manual_path=base/'observer-manual-trigger.json';paths.append(manual_path)
    empty={'sublayerPresent':False,'filters':[]}
    checks={
        'singleRebootRequest':r['rebootCommandAttempts']==1 and r.get('dispatchResult')=='REBOOT_REQUEST_ACCEPTED',
        'requestDuringLease':delta(command['blockUntil'],intent['requestedUtc'])>0,
        'twoDynamicFiltersActiveAtRequest':intent['filterCount']==2 and r['applied']['dynamic'] and not r['applied']['persistent'],
        'actualBootChanged':boot['bootId']!=r['ready']['bootId'] and post['bootId']==boot['bootId'],
        'postBootInventoryEmptyBeforeNewCommands':boot['inventory']==empty and boot['newCommandsAccepted'] is False,
        'oldCommandRejected':any(x['event']=='rejected_or_failed' and x['code']=='STALE_BOOT' for x in stale),
        'rejectedCommandInstalledNoFilters':read(paths[11])['inventory']==empty and post['staleCommandApplied'] is False,
        'isolationStillIndependent':observation.get('isolation',{}).get('isolationRules')==4,
        'trafficRestored':post['connections']['targetNew']['ok'] and post['connections']['controlNew']['ok'] and not post['connections']['deniedThirdPort']['ok'],
        'managementRestored':all(x['status']=='Running' for x in post['services']),
        'inventoryStillEmpty':post['inventory']==empty,
    }
    expected={'targetExisting':False,'targetNew':False,'controlExisting':True,'controlNew':True}
    checks['connectionsBeforeAndDuring']=all(x['ok'] for x in r['before'].values()) and all(r['during'][k]['ok'] is v for k,v in expected.items()) and not r['isolationDeniedPort']['ok']
    observations=[]
    for entry in watch:
        if entry['event']=='actual_filters' and entry['remaining']==0:
            observations.append({'source':'shutdown_read_only_observer','minusDeadlineSeconds':entry['delaySeconds']})
    final_path=folder/'final.json'
    if final_path.exists():
        paths.append(final_path);final=read(final_path)
        if final['inventory']==empty and final['delaySeconds'] is not None:
            observations.append({'source':'pre_boot_independent_watchdog','minusDeadlineSeconds':final['delaySeconds']})
    if boot['inventory']==empty:
        observations.append({'source':'manual_post_boot_observer','minusDeadlineSeconds':delta(boot['observedUtc'],command['blockUntil'])})
    direct=base/'post-reboot-manual-inventory.json';paths.append(direct);manual=read(direct)
    if manual['inventory']==empty:
        observations.append({'source':'timed_manual_inventory','minusDeadlineSeconds':delta(manual['observedUtc'],command['blockUntil'])})
    timely=any(x['minusDeadlineSeconds']<=1 for x in observations)
    automatic_observer=task['lastResult']==0
    strict=all(checks.values()) and timely and automatic_observer
    return {'rebootExecuted':checks['actualBootChanged'],'strictRebootTtlPassed':strict,
            'status':'passed_bounded_reboot_probe' if strict else 'reboot_restoration_verified_deadline_unverified' if all(checks.values()) else 'failed',
            'checks':checks,'expiryVerificationBudgetSeconds':1,
            'requestBeforeDeadlineSeconds':round(delta(command['blockUntil'],intent['requestedUtc']),6),
            'newBootAfterRequestSeconds':round(delta(boot['bootId'],intent['requestedUtc']),6),
            'automaticStartupObserver':{'lastResult':task['lastResult'],'passed':automatic_observer,
                                        'failureCause':'not_established_no_startup_stderr_or_task_history',
                                        'manualDiagnosticSucceeded':observation['status']=='reconciled_no_commands_accepted'},
            'withinDeadlineAbsenceObserved':timely,
            'blockers':([] if timely else ['NO_WITHIN_DEADLINE_ABSENCE_OBSERVATION'])+([] if automatic_observer else ['AUTOMATIC_STARTUP_OBSERVER_FAILED']),
            'trafficVerification':'fresh_independent_isolation_window_after_reboot_no_new_block_installed',
            'actualAbsenceObservations':[{**x,'minusDeadlineSeconds':round(x['minusDeadlineSeconds'],6)} for x in observations],
            'noAdditionalRebootAttempted':True,'productionAutoSupported':False},paths
