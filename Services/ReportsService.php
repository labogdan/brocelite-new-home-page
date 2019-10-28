<?php

namespace App\Services;


use App\Alert;
use App\Jobs\HaveibeenpwnedDomainBreach;
use App\Report;
use App\Vulnerability;
use Illuminate\Database\Eloquent\Collection;

class ReportsService
{
    public static function getCircleCssClassByScores(...$args)
    {
      $optionalStr = '';
      if (isset($args[1])) {
        $optionalStr = '-' . $args[1];
      }

        if ($args[0] < 30) {
            return 'black-circle' . $optionalStr;
        }
        if ($args[0] >= 30 and $args[0] < 50) {
            return 'red-circle' . $optionalStr;
        }
        if ($args[0] >= 50 and $args[0] < 70) {
            return 'orange-circle' . $optionalStr;
        }
        if ($args[0] >= 70 and $args[0] <= 90) {
            return 'yellow-circle' . $optionalStr;
        }
        if ($args[0] > 90) {
            return 'green-circle' . $optionalStr;
        }

    }

    public static function getScoreCSSClass($scores)
    {
        if ($scores < 30) {
            return 'black-score-card';
        }
        if ($scores >= 30 and $scores < 50) {
            return 'red-score-card';
        }
        if ($scores >= 50 and $scores < 70) {
            return 'orange-score-card';
        }
        if ($scores >= 70 and $scores <= 90) {
            return 'yellow-score-card';
        }
        if ($scores > 90) {
            return 'green-score-card';
        }
    }

    public static function getScoreCSSColor($scores)
    {
        if ($scores < 30) {
            return 'black-score-text';
        }
        if ($scores >= 30 and $scores < 50) {
            return 'red-score-text';
        }
        if ($scores >= 50 and $scores < 70) {
            return 'orange-score-text';
        }
        if ($scores >= 70 and $scores <= 90) {
            return 'yellow-score-text';
        }
        if ($scores > 90) {
            return 'green-score-text';
        }
    }

    public static function getLowPercentage(Collection $alerts)
    {
        if ($alerts->count() == 0) {
            return 0;
        }
        return $alerts->where('vulnerability.risk', 'Low')->count() * 100 / $alerts->count();
    }

    public static function getMediumPercentage(Collection $alerts)
    {
        if ($alerts->count() == 0) {
            return 0;
        }
        return $alerts->where('vulnerability.risk', 'Medium')->count() * 100 / $alerts->count();
    }

    public static function getHighPercentage(Collection $alerts)
    {
        if ($alerts->count() == 0) {
            return 0;
        }
        return $alerts->where('vulnerability.risk', 'High')->count() * 100 / $alerts->count();
    }

    /**
     * @param $reportId
     * @return array
     */
    public static function getReportData($reportId): array
    {
        $report = Report::findOrFail($reportId);

        $alerts = Alert::whereHas('scan_job', function ($query) use ($report) {
            $query->where('batch_id', $report->batch_id)->where('domain_id', $report->domain_id);
        })->with('vulnerability')->get();

        $perimeterExposureAlerts = $alerts->where('vulnerability.subcategory',
            Vulnerability::SUBCATEGORIES['PerimeterExposure']);

        $is_domain_detected_on_dark_web = $alerts->where('vulnerability.name',
                HaveibeenpwnedDomainBreach::DETECTION_OF_DOMAIN_ON_THE_DARK_WEB)->count() >= 1;

        if ($perimeterExposureAlerts->where('vulnerability.risk', 'High')->count() == 0) {
            $perimeterExposure_scores = 100;
        }

        if ($perimeterExposureAlerts->where('vulnerability.risk', 'High')->count() == 1) {
            $perimeterExposure_scores = 30;
        }
        if ($perimeterExposureAlerts->where('vulnerability.risk', 'High')->count() > 1) {
            $perimeterExposure_scores = 0;
        }

        $webApplicationRiskAlerts = $alerts->where('vulnerability.subcategory',
            Vulnerability::SUBCATEGORIES['WebApplicationRisk']);
        $networkExposureAlerts = $alerts->where('vulnerability.subcategory',
            Vulnerability::SUBCATEGORIES['NetworkExposure']);
        $webApplicationEncryptionAlerts = $alerts->where('vulnerability.subcategory',
            Vulnerability::SUBCATEGORIES['WebApplicationEncryption']);

        foreach (compact('webApplicationRiskAlerts', 'networkExposureAlerts',
            'webApplicationEncryptionAlerts') as $alert_type => $alerts_collection) {
            $scores_var_name = $alert_type . '_scores';
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Low')->count() == 0
            ) {
                $$scores_var_name = 100;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Low')->count() >= 1 and
                $alerts_collection->where('vulnerability.risk', 'Low')->count() <= 5
            ) {
                $$scores_var_name = 90;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() >= 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() <= 3
            ) {
                $$scores_var_name = 80;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Low')->count() >= 6 and
                $alerts_collection->where('vulnerability.risk', 'Low')->count() <= 10
            ) {
                $$scores_var_name = 85;
            }

            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 0 and
                $alerts_collection->where('vulnerability.risk', 'Medium')->count() > 3
            ) {
                $$scores_var_name = 75;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() == 1
            ) {
                $$scores_var_name = 65;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() >= 2 and
                $alerts_collection->where('vulnerability.risk', 'High')->count() <= 3
            ) {
                $$scores_var_name = 40;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() >= 4 and
                $alerts_collection->where('vulnerability.risk', 'High')->count() <= 5
            ) {
                $$scores_var_name = 25;
            }
            if (
                $alerts_collection->where('vulnerability.risk', 'High')->count() > 5
            ) {
                $$scores_var_name = 5;
            }
        }


        $mailServerSecurityAlerts = $alerts->where('vulnerability.subcategory',
            Vulnerability::SUBCATEGORIES['MailServerSecurity']);
        $mailServerSecurityAlerts_scores = 0;
        if ($mailServerSecurityAlerts->count() == 0) {
            $mailServerSecurityAlerts_scores = 100;
        }
        if ($mailServerSecurityAlerts->where('vulnerability.risk', 'High')->count() == 1) {
            $mailServerSecurityAlerts_scores = 30;
        }
        if ($mailServerSecurityAlerts->where('vulnerability.risk', 'High')->count() > 1) {
            $mailServerSecurityAlerts_scores = 0;
        }

        $overall_score = $perimeterExposure_scores * 0.10 + $networkExposureAlerts_scores * 0.30 +
            $webApplicationRiskAlerts_scores * 0.35 + $webApplicationEncryptionAlerts_scores * 0.15 + $mailServerSecurityAlerts_scores * 0.10;
        $overall_score = (int)round($overall_score);

        $company = $report->getCompany();
        return compact(
            'company',
            'report',
            'alerts',
            'perimeterExposureAlerts',
            'webApplicationEncryptionAlerts',
            'networkExposureAlerts',
            'webApplicationRiskAlerts',
            'mailServerSecurityAlerts',
            'perimeterExposure_scores',
            'webApplicationEncryptionAlerts_scores',
            'networkExposureAlerts_scores',
            'webApplicationRiskAlerts_scores',
            'mailServerSecurityAlerts_scores',
            'overall_score',
            'is_domain_detected_on_dark_web'
        );
    }
}
