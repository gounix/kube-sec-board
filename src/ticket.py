import kanboard


class ticket:
    project_id = -1
    close_message = "Vulnerability no longer detected, closing"
    reopen_message = "Vulnerability detected while ticket is closed, reopening"
    adjust_title_message = "Title changed, old title:"
    adjust_priority_message = "Priority different than trivy, adjusting from %s to %s"
    adjust_color_message = "Color different than trivy, adjusting from %s to %s"
    adjust_description_message = (
        "Description different from previous trivy run, old description: "
    )
    bullet = "- "
    uid = 1
    gid = -1
    default_role = "project-member"

    def __init__(
        self, url: str, user: str, apikey: str, group_name: str, project: str
    ) -> None:
        self.task_list = []
        self.active_tasks = []
        self.user = user
        self.group_name = group_name
        self.project = project
        self.board = kanboard.Client(url, user, apikey)
        self._create_project()
        self._create_group()
        self._add_group()
        self._get_tasks()
        self._get_uid()
        self.new_tickets = 0
        self.updated_tickets = 0
        self.closed_tickets = 0

    def _create_group(self):
        status = self.board.get_all_groups()
        if not status:
            print("ticket._create_group: get_all_groups failed", flush=True)
            return

        existing = [group for group in status if group["name"] == self.group_name]
        print("existing group %s" % (str(existing)), flush=True)
        if existing != []:
            self.gid = existing[0]["id"]
            print(
                "ticket._create_group: group %s exists with id %s"
                % (self.group_name, self.gid),
                flush=True,
            )
            return

        print(
            "ticket._create_group: group %s does not exist" % (self.group_name),
            flush=True,
        )

        status = self.board.create_group(name=self.group_name)
        if not status:
            print(
                "ticket._create_group: create_group %s failed" % (self.group_name),
                flush=True,
            )
            return

        self.gid = status
        print(
            "ticket._create_group: create_group %s succeeded with gid %s"
            % (self.group_name, self.gid),
            flush=True,
        )

    def _add_group(self):
        # er bestaat geen api voor get_project_groups ??
        # status = self.board.get_project_users(project_id=self.project_id)
        # if not status:
        #    print("ticket._add_group: get_project_users %s failed" % (self.project), flush=True)
        #    # failure en lege lijst zelfde?
        #    #return
        # print("get_project_users %s" % (str(status)), flush=True)

        status = self.board.add_project_group(
            project_id=self.project_id, group_id=self.gid, role=self.default_role
        )
        if not status:
            print(
                "ticket._add_group: add_project_group projectid=%s group_id=%s failed, already a member?"
                % (self.project, self.gid),
                flush=True,
            )
            return

        print(
            "ticket._add_group: added group %s to %s" % (self.gid, self.project),
            flush=True,
        )

    def _get_uid(self):
        # http 403 forbidden ??
        # status = self.board.get_me()
        # print("ticket._get_uid: get_me status %s" % (status))
        # status = self.board.get_user_by_name(username=self.user)
        # print("ticket._get_uid: get_user_by_name status %s" % (status))
        # self.uid = status['id']
        # print("ticket._get_uid: uid = %s name = %s" % (self.uid, status['username']))
        self.uid = 1

    def _create_project(self):
        lookup_status = self.board.get_project_by_name(name=self.project)
        if not lookup_status:
            status = self.board.create_project(name=self.project)
            self.project_id = status
            print(
                "ticket._create_project: project %s created %s"
                % (self.project, self.project_id),
                flush=True,
            )
        else:
            self.project_id = lookup_status["id"]
            print(
                "ticket._create_project: project %s already exists" % (self.project),
                flush=True,
            )

    def _get_tasks(self):
        # active tasks
        list = self.board.get_all_tasks(project_id=self.project_id, status_id=1)
        self.task_list = list

        # inactive tasks
        list = self.board.get_all_tasks(project_id=self.project_id, status_id=0)
        self.task_list += list

    def create_task(
        self, title: str, reference: str, color: str, priority: str, messages: str
    ):
        matches = [x for x in self.task_list if x["reference"] == reference]
        if matches == []:
            status = self.board.create_task(
                title=title,
                project_id=self.project_id,
                reference=reference,
                color_id=color,
                priority=priority,
                description=messages,
            )
            if not status:
                print("ticket.create_task: failed", flush=True)
                return
            task_nr = status
            print("ticket.create_task: created task %s" % (task_nr), flush=True)
            self.new_tickets += 1
        else:
            task_nr = matches[0]["id"]
            print("ticket.create_task: task %s already exists" % (task_nr), flush=True)
            self._update_ticket(matches[0], title, reference, color, priority, messages)

        # needed by garbage collector
        self.active_tasks.append(task_nr)

        # refresh task list
        self._get_tasks()

    def _update_ticket(
        self,
        ticket,
        title: str,
        reference: str,
        color: str,
        priority: str,
        messages: str,
    ):
        updated = False
        if ticket["title"] != title:
            updated = True
            self._adjust_title(ticket, title)

        if ticket["description"] != messages:
            updated = True
            self._adjust_message(ticket, messages)

        if ticket["color_id"] != color:
            updated = True
            self._adjust_color(ticket, color)

        if ticket["priority"] != priority:
            updated = True
            self._adjust_priority(ticket, priority)

        if not ticket["is_active"]:
            print("active ticket: %s" % (ticket["is_active"]))
            self._reopen_ticket(ticket["id"])

        if updated:
            updated = True
            self.updated_tickets += 1

    def _adjust_title(self, ticket, title: str):
        id = ticket["id"]
        print("ticket._adjust_title: %s" % (id), flush=True)

        if not self.board.create_comment(
            task_id=id,
            user_id=self.uid,
            content=self.adjust_title_message + ticket["title"],
        ):
            print(
                "ticket._adjust_title: comment on ticket %s failed" % (id), flush=True
            )

        if not self.board.update_task(id=id, title=title):
            print("ticket.update_task: task adjust title %s failed" % (id), flush=True)

    def _adjust_message(self, ticket, messages: str):
        id = ticket["id"]
        print("ticket._adjust_message: %s" % (id), flush=True)

        if not self.board.create_comment(
            task_id=id,
            user_id=self.uid,
            content=self.adjust_description_message + ticket["description"],
        ):
            print(
                "ticket._adjust_message: comment on ticket %s failed" % (id), flush=True
            )

        if not self.board.update_task(id=id, description=messages):
            print(
                "ticket.update_task: task adjust description %s failed" % (id),
                flush=True,
            )

    def _adjust_color(self, ticket, color: int):
        id = ticket["id"]
        print(
            "ticket._adjust_color: %s from %s to %s" % (id, ticket["color_id"], color),
            flush=True,
        )

        if not self.board.create_comment(
            task_id=id,
            user_id=self.uid,
            content=self.adjust_color_message % (ticket["color_id"], color),
        ):
            print(
                "ticket._adjust_color: comment on ticket %s failed" % (id), flush=True
            )

        if not self.board.update_task(id=id, color_id=color):
            print("ticket.update_task: task adjust color %s failed" % (id), flush=True)

    def _adjust_priority(self, ticket, priority: int):
        id = ticket["id"]
        print(
            "ticket._adjust_priority: ticket %s from %s to %s"
            % (id, ticket["priority"], priority),
            flush=True,
        )

        if not self.board.create_comment(
            task_id=id,
            user_id=self.uid,
            content=self.adjust_priority_message % (ticket["priority"], priority),
        ):
            print(
                "ticket._adjust_priority: comment on ticket %s failed" % (id),
                flush=True,
            )

        if not self.board.update_task(id=id, priority=priority):
            print(
                "ticket.update_task: task adjust priority %s failed" % (id), flush=True
            )

    def _reopen_ticket(self, id: int):
        print("ticket._reopen_ticket: reopening %s" % (id), flush=True)

        if not self.board.create_comment(
            task_id=id, user_id=self.uid, content=self.reopen_message
        ):
            print(
                "ticket._reopen_ticket: comment on ticket %s failed" % (id), flush=True
            )

        if not self.board.open_task(task_id=id):
            print("ticket.open_task: task reopen %s failed" % (id), flush=True)

    def _close_ticket(self, id: int):
        print("ticket._close_ticket: closing %s" % (id), flush=True)

        if not self.board.create_comment(
            task_id=id, user_id=self.uid, content=self.close_message
        ):
            print(
                "ticket._close_ticket: comment on ticket %s failed" % (id), flush=True
            )

        if not self.board.close_task(task_id=id):
            print("ticket._close_ticket: closing %s failed" % (id), flush=True)

        self.closed_tickets += 1

    def garbage_collect(self) -> (int, int, int):
        print(
            "ticket.garbage_collect: garbage collector called on %s" % (self.project),
            flush=True,
        )
        tl = [x["id"] for x in self.task_list]
        print("task list %s" % (tl))
        print("active task list %s" % (self.active_tasks))
        dangling = [
            x
            for x in self.task_list
            if x["is_active"] and x["id"] not in self.active_tasks
        ]

        for entry in dangling:
            self._close_ticket(entry["id"])

        print("statistics for %s" % (self.project), flush=True)
        print("new tickets %s" % (self.new_tickets), flush=True)
        print("updated tickets %s" % (self.updated_tickets), flush=True)
        print("closed tickets %s" % (self.closed_tickets), flush=True)
        return self.new_tickets, self.updated_tickets, self.closed_tickets
