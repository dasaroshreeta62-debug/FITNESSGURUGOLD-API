<?php

require_once __DIR__ . '/../services/FitnessAssessmentWorkflow.php';

class FitnessAssessmentController
{
    private FitnessAssessmentWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new FitnessAssessmentWorkflow();
    }

    /**
     * Retrieve the Bearer Token from HTTP request headers.
     */
    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return false;
        }
        return str_replace('Bearer ', '', $headers['Authorization']);
    }

    /**
     * Get JSON or url-encoded request body inputs.
     */
    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            return [];
        }
        return $input;
    }

    /**
     * POST /api/assessments
     */
    public function createAssessment(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->createAssessment($token, $input);
        echo json_encode($response);
    }

    /**
     * GET /api/assessments/(\d+)
     */
    public function getAssessment(int $assessmentId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getAssessment($token, $assessmentId);
        echo json_encode($response);
    }

    /**
     * GET /api/members/(\d+)/assessments
     */
    public function getMemberAssessments(int $memberUserId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getMemberAssessments($token, $memberUserId);
        echo json_encode($response);
    }

    /**
     * GET /api/members/(\d+)/assessments/latest
     */
    public function getLatestMemberAssessment(int $memberUserId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getLatestMemberAssessment($token, $memberUserId);
        echo json_encode($response);
    }
}
