<?php declare(strict_types=1);

namespace DOMJudgeBundle\Controller\API;

use Doctrine\ORM\QueryBuilder;
use DOMJudgeBundle\Entity\Contest;
use DOMJudgeBundle\Entity\ContestProblem;
use DOMJudgeBundle\Helpers\ContestProblemWrapper;
use DOMJudgeBundle\Helpers\OrdinalArray;
use FOS\RestBundle\Controller\Annotations as Rest;
use Swagger\Annotations as SWG;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * @Rest\Route("/api/v4/contests/{cid}/problems", defaults={ "_format" = "json" })
 * @Rest\Prefix("/api/contests/{cid}/problems")
 * @Rest\NamePrefix("problems_")
 * @SWG\Tag(name="Problems")
 * @SWG\Parameter(ref="#/parameters/cid")
 * @SWG\Response(response="404", ref="#/definitions/NotFound")
 * @SWG\Response(response="401", ref="#/definitions/Unauthorized")
 */
class ProblemController extends AbstractRestController implements QueryObjectTransformer
{
    /**
     * Get all the problems for this contest
     * @param Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     * @Rest\Get("")
     * @SWG\Response(
     *     response="200",
     *     description="Returns all the problems for this contest",
     *     @SWG\Schema(
     *         type="array",
     *         @SWG\Items(ref="#/definitions/ContestProblem")
     *     )
     * )
     * @SWG\Parameter(ref="#/parameters/idlist")
     * @throws \Doctrine\ORM\NonUniqueResultException
     */
    public function listAction(Request $request)
    {
        // Make sure we clear the entity manager class, for when this method is called multiple times by internal requests
        $this->entityManager->clear();
        // This method is overwritten, because we need to add ordinal values
        $queryBuilder = $this->getQueryBuilder($request);

        $objects = $queryBuilder
            ->getQuery()
            ->getResult();

        if (isset($ids) && count($objects) !== count($ids)) {
            throw new NotFoundHttpException('One or more objects not found');
        }

        if (empty($objects)) {
            return $this->renderData($request, []);
        }

        $objects = array_map([$this, 'transformObject'], $objects);

        $ordinalArray = new OrdinalArray($objects);
        $objects      = $ordinalArray->getItems();

        if ($request->query->has('ids')) {
            $ids = $request->query->get('ids', []);
            if (!is_array($ids)) {
                throw new BadRequestHttpException('\'ids\' should be an array of ID\'s to fetch');
            }

            $ids = array_unique($ids);

            $objects = [];
            foreach ($ordinalArray->getItems() as $item) {
                /** @var ContestProblemWrapper $contestProblemWrapper */
                $contestProblemWrapper = $item->getItem();
                $contestProblem        = $contestProblemWrapper->getContestProblem();
                if (in_array($contestProblem->getProbid(), $ids)) {
                    $objects[] = $item;
                }
            }

            if (count($objects) !== count($ids)) {
                throw new NotFoundHttpException('One or more objects not found');
            }
        }

        return $this->renderData($request, $objects);
    }

    /**
     * Get the given problem for this contest
     * @param Request $request
     * @param string $id
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \Doctrine\ORM\NonUniqueResultException
     * @Rest\Get("/{id}")
     * @SWG\Response(
     *     response="200",
     *     description="Returns the given problem for this contest",
     *     ref="#/definitions/ContestProblem"
     * )
     * @SWG\Parameter(ref="#/parameters/id")
     */
    public function singleAction(Request $request, string $id)
    {
        // Make sure we clear the entity manager class, for when this method is called multiple times by internal requests
        $this->entityManager->clear();
        // This method is overwritten, because we need to add ordinal values
        $queryBuilder = $this->getQueryBuilder($request);

        if ($request->query->has('ids')) {
            $ids = $request->query->get('ids', []);
            if (!is_array($ids)) {
                throw new BadRequestHttpException('\'ids\' should be an array of ID\'s to fetch');
            }

            $ids = array_unique($ids);

            $queryBuilder
                ->andWhere(sprintf('%s IN (:ids)', $this->getIdField()))
                ->setParameter(':ids', $ids);
        }

        $objects = $queryBuilder
            ->getQuery()
            ->getResult();

        if (isset($ids) && count($objects) !== count($ids)) {
            throw new NotFoundHttpException('One or more objects not found');
        }

        $objects = array_map([$this, 'transformObject'], $objects);

        $ordinalArray = new OrdinalArray($objects);

        $object = null;
        foreach ($ordinalArray->getItems() as $item) {
            /** @var ContestProblemWrapper $contestProblemWrapper */
            $contestProblemWrapper = $item->getItem();
            $contestProblem        = $contestProblemWrapper->getContestProblem();
            if ($contestProblem->getProbid() == $id) {
                $object = $item;
                break;
            }
        }

        if ($object === null) {
            throw new NotFoundHttpException(sprintf('Object with ID \'%s\' not found', $id));
        }

        return $this->renderData($request, $object);
    }

    /**
     * @inheritdoc
     */
    protected function getQueryBuilder(Request $request): QueryBuilder
    {
        $contestId = $this->getContestId($request);
        /** @var Contest $contest */
        $contest = $this->entityManager->getRepository(Contest::class)->find($contestId);

        $queryBuilder = $this->entityManager->createQueryBuilder()
            ->from('DOMJudgeBundle:ContestProblem', 'cp')
            ->join('cp.problem', 'p')
            ->leftJoin('p.testcases', 'tc')
            ->select('cp, p, COUNT(tc.testcaseid) AS testdatacount')
            ->andWhere('cp.cid = :cid')
            ->andWhere('cp.allow_submit = 1')
            ->setParameter(':cid', $contestId)
            ->orderBy('cp.shortname')
            ->groupBy('cp.probid');

        // For non-jury users, only expose the problems after the contest has started
        if (!$this->DOMJudgeService->checkrole('jury') && $contest->getStartTimeObject()->getTimestamp() > time()) {
            $queryBuilder->andWhere('1 = 0');
        }

        return $queryBuilder;
    }

    /**
     * @inheritdoc
     */
    protected function getIdField(): string
    {
        return 'cp.probid';
    }

    /**
     * Transform the given object before returning it from the API
     * @param mixed $object
     * @return mixed
     */
    public function transformObject($object)
    {
        /** @var ContestProblem $problem */
        $problem       = $object[0];
        $testDataCount = (int)$object['testdatacount'];
        return new ContestProblemWrapper($problem, $testDataCount);
    }
}
