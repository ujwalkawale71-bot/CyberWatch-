import { cn } from "../../lib/utils"

export function Container({ className, children, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("mx-auto w-full max-w-[1560px] px-4 sm:px-6 lg:px-8 2xl:px-10", className)} {...props}>
      {children}
    </div>
  )
}
