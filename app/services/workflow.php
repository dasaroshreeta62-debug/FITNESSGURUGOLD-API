<?php

require_once __DIR__ . '/../repositories/model.php';


class Workflow
{   
    private Model $model;
    public function __construct()
    {
        $this->model = new Model();
    }
    public function getAllUsers(): array
    {
        return $this->model->getAllUsers();
    }
}
