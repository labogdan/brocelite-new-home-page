<?php

namespace App\Services;


use App\Alert;
use App\Exceptions\OpenVasCallException;
use App\OpenvasInstance;
use App\ScanJob;
use App\Vulnerability;
use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use SimpleXMLElement;

class OpenVASService
{
    public static function handleReport(ScanJob $open_vas_job): void
    {
        $start_task_output = null;
        $report_ready_status = null;
        $report_output_array = null;
        $create_target_name_output = null;
        $create_task_output = null;
        $openvas_instance = self::getRelatedInstance($open_vas_job);
        Log::alert('Start openVAS job', ['zap_job' => $open_vas_job->toArray()]);
        if (!isset($open_vas_job->id_on_scan_source)) {
            $open_vas_job->update(['status' => ScanJob::STATUS_FAILED]);
            return;
        }
        if (!isset($open_vas_job->report_id_on_scan_source)) { //trying to start task again
            Log::alert('No report ID, trying to start task again');
            $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -S {$open_vas_job->id_on_scan_source}";
            $start_task = exec($command, $start_task_output);
            if ($start_task) {
                $open_vas_job->update(['report_id_on_scan_source' => $start_task_output[0]]);
            }
            return;
        }
        if (!exec("omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -G | grep {$open_vas_job->id_on_scan_source}",
                $report_ready_status) or !isset($report_ready_status[0])) {
            Log::alert('No report status data', ['report ready status' => $report_ready_status]);
            return;
        }
        Log::alert('Report ready status', ['report ready status' => $report_ready_status]);
        if (str_contains($report_ready_status[0], [' New ', ' Stopped '])) {//trying to start task again
            $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -S {$open_vas_job->id_on_scan_source}";
            $start_task = exec($command, $start_task_output);
            if ($start_task) {
                $open_vas_job->update(['report_id_on_scan_source' => $start_task_output[0]]);
            }
            Log::alert('Task in New or Stopped status', ['start_task_output' => $start_task_output]);
            return;
        }
        if (str_contains($report_ready_status[0], ' Done ')) {
            $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} --get-report {$open_vas_job->report_id_on_scan_source}";
            if (!exec($command, $report_output_array)) {
                Log::alert('Can not get report output', ['$report_output_array' => $report_output_array]);
                return;
            }
            Log::alert('Job done', ['report_output_array' => $report_output_array]);
            $report_output = implode("\n", $report_output_array);
            $xml_report = new SimpleXMLElement($report_output);
            foreach ($xml_report->report->results->result as $result) {
                $result = (array)$result;
                Log::alert('result data', [$result]);
                if ($result['threat'] == 'Log') {
                    $open_vas_job->update([
                        'status' => ScanJob::STATUS_FINISHED,
                        'completion_date' => Carbon::now(),
                    ]);
                }
                if (str_contains($result['name'], 'SSL/TLS')) {
                    $subcategory = Vulnerability::SUBCATEGORIES['WebApplicationEncryption'];
                } else {
                    $subcategory = Vulnerability::SUBCATEGORIES['NetworkExposure'];
                }
                $vulnerability = Vulnerability::firstOrCreate([
                    'name' => $result['name'],
                    'risk' => $result['threat'],
                    'description' => $result['description'] ?? '',
                    'scan_source_id' => $open_vas_job->scan_source_id,
                    'subcategory' => $subcategory
                ]);
                Alert::firstOrCreate([
                    'count' => 1,
                    'scan_job_id' => $open_vas_job->id,
                    'vulnerability_id' => $vulnerability->id
                ]);
            }
            $open_vas_job->update([
                'status' => ScanJob::STATUS_FINISHED,
                'completion_date' => Carbon::now(),
            ]);
        }
    }

    public static function getRelatedInstance(ScanJob $open_vas_job)
    {
        Log::alert('getRelatedInstance', [$open_vas_job, $open_vas_job->additional_info['openvas_instance_id']]);
        if (empty($open_vas_job->additional_info['openvas_instance_id'])) {
            return self::getInstanceWithMaxLevelOfFreeResources();
        }
        return OpenvasInstance::find($open_vas_job->additional_info['openvas_instance_id']);
    }

    public static function getInstanceWithMaxLevelOfFreeResources()
    {
        $out = null;
        $err = null;
        $openvas_instances = OpenvasInstance::whereIsActive(1)->get();
        foreach ($openvas_instances as $openvas_instance) {
            exec("omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -G",
                $out, $err);
            if ($err === 0) {
                $active_scanes_count = collect($out)->filter(function ($value) {
                    return str_contains($value, ['Running', 'Requested']);
                })->count();
                $openvas_instance->free_resources = $openvas_instance->max_scans - $active_scanes_count;
            } else {
                $openvas_instance->free_resources = -100;
            }
            $out = null;
            $err = null;
        }
        $openvas_instance_max_resources = $openvas_instances->firstWhere('free_resources',
            $openvas_instances->max('free_resources'));
        if ($openvas_instance_max_resources->free_resources <= 0) {
            Log::alert('No OpenVAS instances with free resources');
            return null;
        }
        return $openvas_instance_max_resources;

    }

    public static function startScan(ScanJob $scanJob)
    {
        if (Cache::get('scan_job_status_' . $scanJob->id) === 'started') {
            return;
        }
        Cache::forever('scan_job_status_' . $scanJob->id, 'started');
        $start_task_output = null;
        $report_ready_status = null;
        $report_output_array = null;
        $create_target_name_output = null;
        $create_task_output = null;

        $openvas_instance = self::getInstanceWithMaxLevelOfFreeResources();
        if (!$openvas_instance instanceof OpenvasInstance) {
            Cache::forget('scan_job_status_' . $scanJob->id);
            return;
        }
        $target_name = $scanJob->domain->name . Str::uuid();

        $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} --xml=\"<create_target><name>{$target_name}</name><hosts>{$scanJob->domain->name}</hosts><alive_tests>Consider Alive</alive_tests></create_target>\"";
        $create_target = exec($command, $create_target_name_output);
        Log::alert('create_target_name_output', [$create_target_name_output]);

        if (!$create_target) {
            Cache::forget('scan_job_status_' . $scanJob->id);
            throw new OpenVasCallException('Can not create target');
        }
        $target_id = new SimpleXMLElement($create_target_name_output[0]);
        $target_id = (array)$target_id;
        $target_id = $target_id['@attributes']['id'];
        Log::alert('$target_id', [$target_id]);

        //daba56c8-73ec-11df-a475-002264764cea is ID of  "Full and fast" scan
        $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -C -n {$scanJob->domain->name} --target={$target_id} --config=698b7e56-606b-446d-b9e0-95b0e27a7953";
        $create_task = exec($command, $create_task_output);
        Log::alert('command to create_task', [$command]);
        Log::alert('create_task_output', [$create_task_output]);
        sleep(15);
        if (!$create_task) {
            Cache::forget('scan_job_status_' . $scanJob->id);
            throw new OpenVasCallException('Can not create task');
        }
        $task_id = $create_task_output[0];
        $scanJob->update([
            'status' => ScanJob::STATUS_IN_PROGRESS,
            'start_date' => Carbon::now(),
            'id_on_scan_source' => $task_id,
        ]);
        Log::alert('$task_id', [$task_id]);
        sleep(15);

        $command = "omp -u {$openvas_instance->username} -w {$openvas_instance->password} -h {$openvas_instance->hostname} -p {$openvas_instance->port} -S {$task_id}";
        $start_task = exec($command, $start_task_output);
        Log::alert('command to start_task', [$command]);
        Log::alert('start_task_output', [$start_task_output]);

        if (!$start_task) {
            Cache::forget('scan_job_status_' . $scanJob->id);
            exec('openvassd');
            throw new OpenVasCallException('Can not start task');
        }
        $report_id = $start_task_output[0];
        Log::alert('$report_id', [$report_id]);

        $scanJob->update([
            'report_id_on_scan_source' => $report_id,
            'additional_info' => ['openvas_instance_id' => $openvas_instance->id],
        ]);
        sleep(15);
    }
}