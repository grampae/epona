from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload to the target",
            ),
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Absolute destination path on the target",
            ),
        ]

    async def parse_arguments(self):
        raise ValueError("Upload requires the file picker — use the task UI")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the target using Mythic's chunked file transfer protocol"
    version = 1
    author = "@grampae"
    attackmapping = ["T1105"]
    argument_class = UploadArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.MacOS, SupportedOS.Windows],
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = f"{task.args.get_arg('path')}"
        return task

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
