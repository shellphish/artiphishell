import os

from .skill import Skill, SkillRepository
from .builder import SkillBuilder, SkillBuilderCurriculum, SkillPlanStep, SkillPlanner, SkillBuilderCritic

Skills_Neo4J = SkillRepository('neo4j')

def add_skill_from_python_file(fpath: str, repo: SkillRepository):
    name = os.path.basename(fpath).rsplit('.', 1)[0]
    existing = repo.get_by_name(name)

    with open(fpath, 'r') as f:
        source = f.read()

    is_changed = False
    if existing:
        skill = existing
    else:
        skill = Skill(name=name, description='')
        is_changed = True

    description = source.split('\n', 1)[0].strip('# ')
    if skill.description != description:
        skill.description = description
        is_changed = True

    source_ptr = f'file://{os.path.abspath(fpath)}'
    if skill.source_ptr != source_ptr:
        skill.source_ptr = source_ptr
        is_changed = True
    
    if is_changed:
        repo.add_skill(skill)

def sync_base_neo4j_skills():
    '''
    target_dir = './query_guy/query_primitives_context/'
    for fn in os.listdir(target_dir):
        if fn.endswith('.py'):
            fpath = os.path.join(target_dir, fn)
            add_skill_from_python_file(fpath, Skills_Neo4J)
    '''

#sync_base_neo4j_skills()