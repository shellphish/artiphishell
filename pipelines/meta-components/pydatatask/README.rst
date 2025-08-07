pydatatask is a library for building data pipelines.
Sounds familiar?
The cool part here is that you are not restricted in the way your data is stored or the way your tasks are executed.

Installing
----------

``pip install pydatatask``

Nomenclature
------------

A **task** is one phase of computation.
It is parameterized (instantiated) by a single **job** that it is currently working on.
A **pipeline** is a collection of tasks.
Tasks read and write data from **repositories**, which are arbitrary key-value stores.

The way your data is stored
---------------------------

`Repository` classes are the core of pydatatask.
You can store your data in any way you desire and as long as you can write a repository class to describe it, it can be used to drive a pipeline.

The notion of the "value" part of the key-value store abstraction is defined very, very loosely.
The repository base class doesn't have an interface to get or store values, only to query for and delete keys.
Instead, you have to know which repository subclass you're working with, and use its interfaces.
For example, `MetadataRepository` assumes that its values are structured objects and loads them fully into memory, and `BlobRepository` provides a streaming interface to a flat address space.

Current in-tree repositories:

- In-memory dicts
- Files or directories on the local filesystem
- S3 or compatible buckets
- MongoDB collections
- Docker repositories
- Various combinators

The way your tasks are executed
-------------------------------

A `Task` is connected to repositories through `links <Link>`. A link is a repository plus a collection of properties describing the repository's relationship to the task - i.e. whether it is input or output, whether it should inhibit dependent tasks from starting, etc.

Current in-tree task types:

- In-process python function execution
- Python function execution with the help of a concurrent.futures Executor
- Python function execution on a kubernetes cluster
- Script execution on a kubernetes cluster
- Script execution locally or over SSH

Most tasks define the notion of an **environment** which is used to template the task for the particular job that is being run.

Management of resources: the Session
------------------------------------

A `Session` is a tool for managing multiple live resources.
After constructing a session, you can register async resource manager routines.
You will receive in return a callable which will return the live resource while the session is opened.
This means that a pipeline and all its resources can be defined in a synchronous context, and then allocated and connected whenthe async context is activated.

Putting it together: the Pipeline object
----------------------------------------

A `Pipeline` is just an unordered collection of tasks paired with a Session.
Relationships between the tasks are implicit, defined by which repositories they share.

Example
-------

.. code:: python

    import os
    import aiobotocore.session
    import pydatatask

    session = pydatatask.Session()

    @session.resource
    async def bucket():
        bucket_session = aiobotocore.session.get_session()
        async with bucket_session.create_client(
            's3',
            endpoint_url=os.getenv('BUCKET_ENDPOINT'),
            aws_access_key_id=os.getenv("BUCKET_USERNAME"),
            aws_secret_access_key=os.getenv("BUCKET_PASSWORD"),
        ) as client:
            yield client

    books_repo = pydatatask.S3BucketRepository(bucket, "books/", '.txt')
    done_repo = pydatatask.YamlMetadataFileRepository('./results/')
    reports_repo = pydatatask.FileRepository('./reports', '.txt')

    @pydatatask.InProcessSyncTask('summary', done_repo)
    async def summary(job: str, books: pydatatask.S3BucketRepository, reports: pydatatask.FileRepository):
        paragraphs, lines, words, chars = 0, 0, 0, 0
        async with await books.open(job, 'r') as fp:
            data = await fp.read()
        for line in data.splitlines():
            if line.strip() == '':
                paragraphs += 1
            lines += 1
            words += len(line.split())
            chars += len(line)
        async with await reports.open(job, 'w') as fp:
            await fp.write(f'The book "{job}" has {paragraphs} paragraphs, {lines} lines, {words} words, and {chars} characters.\n')

    summary.link('books', books_repo, is_input=True)
    summary.link('reports', reports_repo, is_output=True)

    pipeline = pydatatask.Pipeline([summary], session)

    if __name__ == '__main__':
        pydatatask.main(pipeline)
