"""Docker-related exceptions for MrZero."""


class DockerError(Exception):
    """Base exception for Docker-related errors."""

    pass


class DockerNotInstalledError(DockerError):
    """Raised when Docker is not installed or not running."""

    def __init__(self, message: str | None = None):
        super().__init__(
            message
            or "Docker is not installed or not running. "
            "Please install Docker: https://docs.docker.com/get-docker/"
        )


class ImageNotFoundError(DockerError):
    """Raised when a Docker image is not found."""

    def __init__(self, image: str):
        super().__init__(
            f"Docker image '{image}' not found. Run 'mrzero docker pull' to download it."
        )
        self.image = image


class ContainerError(DockerError):
    """Raised when a container operation fails."""

    def __init__(self, message: str, exit_code: int | None = None):
        super().__init__(message)
        self.exit_code = exit_code
