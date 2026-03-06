"""Entry point for the sample package."""

from .core import compute, get_platform


def main() -> None:
    """Run the sample computation and print results."""
    result = compute(10)
    platform = get_platform()
    print(f"Result: {result}, platform: {platform}")


if __name__ == "__main__":
    main()
