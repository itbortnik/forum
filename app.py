from sqlalchemy import func
from data.db_session import create_session
from data.models.departments import Department
from data.models.users import User
from data.models.jobs import Jobs


def get_employees_with_hours():
    session = create_session()

    employees = session.query(User). \
        join(Department, User.department_id == Department.id). \
        join(Jobs, User.id == Jobs.user_id). \
        filter(Department.id == 1). \
        group_by(User.id). \
        having(func.sum(Jobs.work_hours) > 25). \
        all()

    for emp in employees:
        print(f"{emp.surname} {emp.name}")


if __name__ == "__main__":
    get_employees_with_hours()
